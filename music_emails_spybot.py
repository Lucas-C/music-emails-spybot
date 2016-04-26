#!/usr/bin/env python3

# INSTALL: pip install --user Jinja2 requests
# USAGE: ./music_emails_spybot.py ComfySpy --email-subject Comfy --imap-username lucascimon --imap-password $IMAP_PASSWORD --ignored-links-pattern 'novaplanet\.com|urbandictionary\.com|xkcd\.com|\.gif$|\.jpe?g$'
#  jq -r '.rawdata["17302"]["text/plain"]' < ComfySpy_bot_memory.json

import argparse, email, html, json, re, requests, os, sys
from collections import defaultdict
from email.header import decode_header
from email.utils import parsedate_to_datetime
from imaplib import IMAP4_SSL
from jinja2 import Environment, FileSystemLoader

THIS_SCRIPT_PARENT_DIR = os.path.dirname(os.path.realpath(__file__))

HEADER_EMAIL_SPLITTER_RE = re.compile(', ?\r?\n?\t?')
HEADER_EMAIL_USER_ADDRESS_RE = re.compile(r'"?(cc:\s*)?([^"]+)"?\s+<(.+)>', re.DOTALL)
HEADER_EMAIL_ADDRESS_RE = re.compile(r'[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}')
CONTENT_LINK_TAGS_RE = re.compile(r'<a\s+href="?(http[^> "]*)"?\s*>([^<]*)</a>', re.DOTALL)

def main(argv=sys.argv[1:]):
    args = parse_args(argv)
    archive = load_archive_from_file(args.project_name)
    msgs = imap_get_new_msgs(args.email_subject, archive['rawdata'].keys(), args.imap_username, args.imap_password,
                             args.imap_server_name, args.imap_server_port, args.imap_mailbox)
    archive['rawdata'].update(extract_rawdata(msgs))
    save_archive_to_file(args.project_name, archive) # This first dump to disk ensure we won't have to fetch the server even if the following fails
    archive['emails'] = extract_emails(archive['rawdata'], args.ignored_links_pattern)
    get_youtube_song_names(archive)
    archive['users'] = compute_users_stats(archive['emails'])
    save_archive_to_file(args.project_name, archive)
    allmembers_email_dest = ';'.join(user_email for user_email, user in archive['users'].items() if user['emails_sent'])
    generates_html_report(archive, args.project_name, args.email_subject, allmembers_email_dest)

def parse_args(argv):
    parser = argparse.ArgumentParser(description='Generates an HTML report of all mentioned songs in emails retrieved from IMAP server (e.g. Gmail)',
                                     formatter_class=ArgparseHelpFormatter)
    parser.add_argument('--imap-username', required=True, help='Your Gmail account name')
    parser.add_argument('--imap-password', required=True, help="With Gmail you'll need to generate an app password on https://security.google.com/settings/security/apppasswords")
    parser.add_argument('--email-subject', required=True)
    parser.add_argument('--ignored-links-pattern', default=r'\.gif$|\.jpe?g$')
    parser.add_argument('--imap-mailbox', default='"[Gmail]/Tous les messages"')
    parser.add_argument('--imap-server-name', default='imap.gmail.com')
    parser.add_argument('--imap-server-port', type=int, default=993)
    parser.add_argument('project_name')
    return parser.parse_args(argv)

class ArgparseHelpFormatter(argparse.RawTextHelpFormatter, argparse.ArgumentDefaultsHelpFormatter):
    pass

def load_archive_from_file(project_name):
    print('Now loading archive from disk file')
    db_file_path = os.path.join(THIS_SCRIPT_PARENT_DIR, project_name + '_bot_memory.json')
    try:
        with open(db_file_path, 'r') as archive_file:
            return json.load(archive_file)
    except FileNotFoundError:
        return {'rawdata': {}, 'emails': {}, 'users': {}}

def save_archive_to_file(project_name, archive):
    print('Now saving archive to disk file')
    db_file_path = os.path.join(THIS_SCRIPT_PARENT_DIR, project_name + '_bot_memory.json')
    with open(db_file_path, 'w') as archive_file:
        json.dump(archive, archive_file)

def imap_get_new_msgs(email_subject, already_fetched_ids, user, password, server_name, server_port, mailbox):
    imap = IMAP4_SSL(server_name, server_port)
    try:
        return_code, msgids = imap.login(user, password)
        assert msgids[0].endswith(b' authenticated (Success)') and return_code == 'OK'
        return_code, msgids = imap.select(mailbox=mailbox, readonly=True)
        assert return_code == 'OK'
        print('Now searching for messages in {} matching subject "{}"'.format(mailbox, email_subject))
        return_code, msgids = imap.search(None, 'SUBJECT', email_subject)
        assert return_code == 'OK' and len(msgids) == 1
        msgids = msgids[0].decode('ascii').split(' ')
        msgids = set(msgids) - set(already_fetched_ids)
        print('Now fetching {} new messages'.format(len(msgids)))
        msgs = {id: imap.fetch(id.encode('ascii'), '(RFC822)') for id in msgids}
        assert all(msg[0] == 'OK' for msg in msgs.values())
        return msgs
    finally:
        imap.logout()

def extract_rawdata(msgs):
    print('Now extracting raw data from {} fetched messages'.format(len(msgs)))
    email_msgs = {id: email.message_from_string(decode_ffs(msg[1][0][1])) for id, msg in msgs.items()}
    rawdata = {id: {'Date': msg.get('Date'), 'From': msg.get('From'), 'To': msg.get('To'), 'Cc': msg.get('Cc')} for id, msg in email_msgs.items()}
    rawdata = nested_merge(rawdata, {id: {'text/html': get_msg_content(msg.get_payload(), 'text/html')} for id, msg in email_msgs.items()})
    rawdata = nested_merge(rawdata, {id: {'text/plain': get_msg_content(msg.get_payload(), 'text/plain')} for id, msg in email_msgs.items()})
    return rawdata

def get_msg_content(msgs, target_content_type):
    if isinstance(msgs, str):
        return msgs
    if any(msg.get_content_type() == 'multipart/alternative' for msg in msgs):
        return get_msg_content([msg.get_payload() for msg in msgs if msg.get_content_type() == 'multipart/alternative'][0], target_content_type)
    if any(msg.get_content_type() == target_content_type for msg in msgs):
        return html.unescape(decode_ffs([msg.get_payload(decode=True) for msg in msgs if msg.get_content_type() == target_content_type][0]))
    assert False

def decode_ffs(bytestring):  # Decode this bytestring for fuck's sake
    try:
        return bytestring.decode('utf8')
    except UnicodeError:
        return bytestring.decode('latin1')

def nested_merge(*dicts):
    result = defaultdict(dict)
    for d in dicts:
        for k, v in d.items():
            result[k].update(v)
    return result

def extract_emails(rawdata, ignored_links_pattern):
    print('Now extracting meaningful info from raw data')
    emails = {id: format_date(datum['Date']) for id, datum in rawdata.items()}
    emails = nested_merge(emails, {id: extract_src_dst(datum) for id, datum in rawdata.items()})
    emails = nested_merge(emails, {id: {'links': list(extract_links(datum, ignored_links_pattern))} for id, datum in rawdata.items()})
    return emails

def format_date(date):
    dt = parsedate_to_datetime(date)
    return {'timestamp': dt.timestamp(), 'date_str': dt.strftime('%Y-%m-%d %H:%M')}

def extract_src_dst(rawdatum):
    src_user_email, src_user_name = extract_user_email_and_name(rawdatum['From'])
    dests = HEADER_EMAIL_SPLITTER_RE.split(rawdatum['To']) + (HEADER_EMAIL_SPLITTER_RE.split(rawdatum['Cc']) if rawdatum['Cc'] else [])
    return {'src': {src_user_email: src_user_name},
            'dests': {email: name for email, name in (extract_user_email_and_name(dest) for dest in dests)}}

def extract_user_email_and_name(address):
    match = HEADER_EMAIL_USER_ADDRESS_RE.match(address.strip())
    if match:
        user_name_label, user_email = match.group(2, 3)
        user_name, charset = decode_header(user_name_label)[0]
        if charset:
            user_name = user_name.decode(charset)
        user_name = re.sub(r'\s+', ' ', user_name)
    else:
        user_email = HEADER_EMAIL_ADDRESS_RE.match(address.strip().lower()).group()
        user_name = ''
    return user_email.lower(), user_name

def extract_links(email_msg, ignored_links_pattern):
    for match in re.findall(CONTENT_LINK_TAGS_RE, email_msg['text/html']):
        url, text = match
        if re.search(ignored_links_pattern, url):
            print('- Ignoring link {} ({})'.format(text, url))
            continue
        text = re.sub(r'\s+', ' ', text.strip())
        plain_text_content = re.sub('<(?!' + re.escape(url) + ')[^>]+>', '', email_msg['text/plain'])
        if text == url:
            regex = re.escape(url)
        else:
            regex = re.sub(r'\\\s+', r'\s+', re.escape(text)) + r'\s*<' + re.escape(url) + '>'
        match = re.search('[^.!?]*' + regex + '[^.!?]*[.!?]*', plain_text_content, re.DOTALL)
        if not match:
            regex = re.sub(r'\\\s+', r'\s+', re.escape(text))
            match = re.search('[^.!?]*' + regex + '[^.!?]*[.!?]*', plain_text_content, re.DOTALL)
        quote = match.group().strip()
        quote = re.sub(r'\s+', ' ', quote)
        quote = re.sub(regex, '<a href="{}">{}</a>'.format(url, text), quote)
        yield {'url': url, 'quote': quote, 'text': text}

def get_youtube_song_names(archive):
    print('Now getting names of Youtube songs')
    if 'youtube_song_names_cache' not in archive:
        archive['youtube_song_names_cache'] = {}
    youtube_song_names_cache = archive['youtube_song_names_cache']
    for _, email_msg in archive['emails'].items():
        for link in email_msg['links']:
            if re.search(r'https?://(youtu\.be|(www\.)?youtube\.com)/.+', link['url']):
                if link['url'] not in youtube_song_names_cache:
                    youtube_song_names_cache[link['url']] = get_page_title(link['url'])
                link['youtube_song_name'] = youtube_song_names_cache[link['url']]

def get_page_title(url):
    response = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'})
    response.raise_for_status()
    return re.search('<title>([^<]+)</title>', response.text).group(1)

def compute_users_stats(emails):
    users = {}
    def add_user(user_email, user_name):
        if user_email not in users:
            users[user_email] = {'name': user_name, 'emails_received': 0, 'emails_sent': 0}
        if '@' in users[user_email]['name']:
            users[user_email]['name'] = user_name
    for _, email_msg in emails.items():
        user_email, user_name = list(email_msg['src'].items())[0]
        add_user(user_email, user_name)
        users[user_email]['emails_sent'] += 1
        for user_email, user_name in email_msg['dests'].items():
            add_user(user_email, user_name)
            users[user_email]['emails_received'] += 1
    assert len(emails) == sum(user['emails_sent'] for user_email, user in users.items())
    return users

def generates_html_report(archive, project_name, email_subject, allmembers_email_dest):
    print('Now generating the HTML report')
    env = Environment(loader=FileSystemLoader(THIS_SCRIPT_PARENT_DIR))
    #env.filters['format_date'] = jinja_format_date
    template = env.get_template('music_emails_spybot_report_template.html')
    html_report_path = os.path.join(THIS_SCRIPT_PARENT_DIR, project_name + '.html')
    with open(html_report_path, 'w') as report_file:
        report_file.write(template.render(project_name=project_name, email_subject=email_subject, allmembers_email_dest=allmembers_email_dest, **archive))

if __name__ == '__main__':
    main()
