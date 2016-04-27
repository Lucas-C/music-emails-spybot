#!/usr/bin/env python3

#  jq 'del(.rawdata)' < ComfySpy_bot_memory.json | sponge ComfySpy_bot_memory.json
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
CATEGORY_HASHTAGS_RE = re.compile(r'(^|\s)#([a-zA-Z][a-zA-Z0-9_]+)(\s|$)')

def main(argv=sys.argv[1:]):
    args = parse_args(argv)
    archive = load_archive_from_file(args.project_name)
    msgs = imap_get_new_msgs(args.email_subject, archive['rawdata'].keys(), args.imap_username, args.imap_password,
                             args.imap_server_name, args.imap_server_port, args.imap_mailbox)
    archive['rawdata'].update(extract_rawdata(msgs))
    save_archive_to_file(args.project_name, archive) # This first dump to disk ensure we won't have to fetch the server even if the following fails
    emails = extract_emails(archive['rawdata'], args.ignored_links_pattern)
    add_page_titles(archive['page_titles_cache'], emails)
    save_archive_to_file(args.project_name, archive)
    users = aggregate_users(emails)
    fix_usernames(users, args.project_name)
    archive['stats'] = compute_stats(emails)
    archive['allmembers_email_dest'] = ';'.join(user_email for user_email, user in users.items()
                                                           if archive['stats']['users'][user['name']]['emails_sent'])
    archive['links'] = [link for email_msg in emails.values()
                             for link in email_msg['links']]
    generates_html_report(archive, args.project_name, args.email_subject)

def parse_args(argv):
    parser = argparse.ArgumentParser(description='Generates an HTML report of all mentioned songs in emails retrieved from IMAP server (e.g. Gmail)',
                                     formatter_class=ArgparseHelpFormatter)
    parser.add_argument('--imap-username', required=True, help='Your Gmail account name')
    parser.add_argument('--imap-password', required=True, help="With Gmail you'll need to generate an app password on https://security.google.com/settings/security/apppasswords")
    parser.add_argument('--email-subject', required=True)
    parser.add_argument('--ignored-links-pattern', default=r'\.gif$|\.jpe?g$', help=' ')
    parser.add_argument('--imap-mailbox', default='"[Gmail]/Tous les messages"', help=' ')
    parser.add_argument('--imap-server-name', default='imap.gmail.com', help=' ')
    parser.add_argument('--imap-server-port', type=int, default=993, help=' ')
    parser.add_argument('project_name')
    return parser.parse_args(argv)

class ArgparseHelpFormatter(argparse.RawTextHelpFormatter, argparse.ArgumentDefaultsHelpFormatter):
    pass

def load_archive_from_file(project_name):
    print('Now loading archive from disk file')
    db_file_path = os.path.join(THIS_SCRIPT_PARENT_DIR, project_name + '_bot_memory.json')
    try:
        with open(db_file_path, 'r') as archive_file:
            archive = json.load(archive_file)
    except (FileNotFoundError, ValueError):
        archive = {}
    archive['rawdata'] = archive.get('rawdata', {})
    archive['page_titles_cache'] = archive.get('page_titles_cache', {})
    return archive

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
    nested_merge(rawdata, {id: {'text/html': get_msg_content(msg.get_payload(), 'text/html')} for id, msg in email_msgs.items()})
    nested_merge(rawdata, {id: {'text/plain': get_msg_content(msg.get_payload(), 'text/plain')} for id, msg in email_msgs.items()})
    return rawdata

def get_msg_content(msgs, target_content_type):
    if isinstance(msgs, str):
        return msgs
    if any(msg.get_content_type() == 'multipart/alternative' for msg in msgs):
        return get_msg_content([msg.get_payload() for msg in msgs if msg.get_content_type() == 'multipart/alternative'][0], target_content_type)
    if any(msg.get_content_type() == target_content_type for msg in msgs):
        return html.unescape(decode_ffs([msg.get_payload(decode=True) for msg in msgs if msg.get_content_type() == target_content_type][0]))
    raise NotImplementedError('Unsupported Content-Types: {}'.format([msg.get_content_type() for msg in msgs]))

def decode_ffs(bytestring):  # Decode this bytestring for fuck's sake
    try:
        return bytestring.decode('utf8')
    except UnicodeError:
        return bytestring.decode('latin1')

def nested_merge(dst, src):
    for k, v in src.items():
        dst[k].update(v)

def extract_emails(rawdata, ignored_links_pattern):
    print('Now extracting meaningful info from raw data')
    emails = {id: {'id': id} for id in rawdata.keys()}
    nested_merge(emails, {id: format_date(datum['Date']) for id, datum in rawdata.items()})
    nested_merge(emails, {id: extract_src_dst(datum) for id, datum in rawdata.items()})
    nested_merge(emails, {id: {'links': list(extract_links(datum, ignored_links_pattern, emails[id]))} for id, datum in rawdata.items()})
    return emails

def format_date(date):
    dt = parsedate_to_datetime(date)
    return {'timestamp': dt.timestamp(), 'date_str': dt.strftime('%Y-%m-%d %H:%M')}

def extract_src_dst(rawdatum):
    src_user_email, src_user_name = extract_user_email_and_name(rawdatum['From'])
    dests = HEADER_EMAIL_SPLITTER_RE.split(rawdatum['To']) + (HEADER_EMAIL_SPLITTER_RE.split(rawdatum['Cc']) if rawdatum['Cc'] else [])
    return {'src': {src_user_email: {'name': src_user_name}},  # only one item in there
            'dests': {email: {'name': name} for email, name in (extract_user_email_and_name(dest) for dest in dests)}}

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

def extract_links(rawdatum, ignored_links_pattern, email_msg):
    for match in re.findall(CONTENT_LINK_TAGS_RE, rawdatum['text/html']):
        url, text = match
        if re.search(ignored_links_pattern, url):
            print('- Ignoring link {} ({})'.format(text, url))
            continue
        text = re.sub(r'\s+', ' ', text.strip())
        quote, regex = extract_quote(text, url, rawdatum['text/plain'])
        tags = set(extract_tags(quote))
        if 'truc' in quote:
            quote = quote.replace('truc', '#truc')
            tags.add('truc')
        quote = re.sub(regex, '<a href="{}">{}</a>'.format(url, text), quote)
        for tag in tags:
            quote = re.sub('#'+tag, '<a href="#{0}">#{0}</a>'.format(tag), quote)
        yield {'url': url, 'quote': quote, 'text': text, 'tags': tags, 'email': email_msg}

def extract_quote(text, url, plain_text_content):
    plain_text_content = re.sub('<(?!' + re.escape(url) + ')[^>]+>', '', plain_text_content)
    plain_text_content = re.sub('(?!' + re.escape(url) + r')http[^\s]+\?[^\s]+', '', plain_text_content)
    if text == url:
        regex = re.escape(url)
    else:
        regex = re.sub(r'\\\s+', r'\s+', re.escape(text)) + r'\s*<' + re.escape(url) + '>'
    match = re.search(r'(^|[.!?]|\n\s*\n)([^.!?](?!\n\s*\n))*?' + regex + r'[^.!?]*?([.!?]|\n\s*\n|$)', plain_text_content, re.DOTALL)
    if not match:
        regex = re.sub(r'\\\s+', r'\s+', re.escape(text))
        match = re.search(r'(^|[.!?]|\n\s*\n)([^.!?](?!\n\s*\n))*?' + regex + r'[^.!?]*?([.!?]|\n\s*\n|$)', plain_text_content, re.DOTALL)
    quote = match.group().strip()
    if quote[0] in '.!?':
        quote = quote[1:]
    return re.sub(r'\s+', ' ', quote).strip(), regex

def extract_tags(quote):
    for match in re.findall(CATEGORY_HASHTAGS_RE, quote):
        yield match[1]

def add_page_titles(page_titles_cache, emails):
    print('Now getting titles of all linked pages')
    for email_msg in emails.values():
        for link in email_msg['links']:
            if link['url'] not in page_titles_cache:
                page_titles_cache[link['url']] = get_page_title(link['url'])
            link['page_title'] = page_titles_cache[link['url']]

def get_page_title(url):
    try:
        response = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'})
        response.raise_for_status()
    except requests.exceptions.RequestException as error:
        print(error)
        return ''
    match = re.search('<title>([^<]+)</title>', response.text)
    if match:
        return match.group(1)
    else:
        return ''

def aggregate_users(emails):
    print('Now aggregating users based on their emails')
    users = {}
    def merge_user(user_email, user):
        if user_email not in users:
            users[user_email] = user
        elif '@' in users[user_email]['name']:
            users[user_email]['name'] = user['name']
        return users[user_email]
    for email_msg in emails.values():
        for user_email, user in email_msg['src'].items():  # only one item in there
            email_msg['src'][user_email] = merge_user(user_email, user)
        for user_email, user in email_msg['dests'].items():
            email_msg['dests'][user_email] = merge_user(user_email, user)
    return users

def fix_usernames(users, project_name):
    usernames_filepath = os.path.join(THIS_SCRIPT_PARENT_DIR, project_name + '_imap_usernames.json')
    if not os.path.exists(usernames_filepath):
        return
    print('Now fixing the users names')
    with open(usernames_filepath, 'r') as usernames_file:
        correct_usernames = json.load(usernames_file)
    for user_email, user in users.items():
        if user_email in correct_usernames:
            user['name'] = correct_usernames[user_email]

def compute_stats(emails):
    print('Now computing some interesting statistics')
    stats = {}
    users_stats = stats['users'] = defaultdict(lambda: defaultdict(int))
    for email_msg in emails.values():
        for user in email_msg['src'].values():  # only one item in there
            user_stats = users_stats[user['name']]
            user_stats['emails_sent'] += 1
            user_stats['links_shared'] += len(email_msg['links'])
        for user in email_msg['dests'].values():
            user_stats = users_stats[user['name']]
            user_stats['emails_received'] += 1
    assert len(emails) == sum(user_stats['emails_sent'] for user_name, user_stats in users_stats.items())
    return stats

def generates_html_report(archive, project_name, email_subject):
    print('Now generating the HTML report')
    env = Environment(loader=FileSystemLoader(THIS_SCRIPT_PARENT_DIR))
    #env.filters['format_date'] = jinja_format_date
    template = env.get_template('music_emails_spybot_report_template.html')
    html_report_path = os.path.join(THIS_SCRIPT_PARENT_DIR, project_name + '.html')
    with open(html_report_path, 'w') as report_file:
        report_file.write(template.render(project_name=project_name, email_subject=email_subject, **archive))

if __name__ == '__main__':
    main()
