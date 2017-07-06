#!/usr/bin/env python3

#  jq '.rawdata|with_entries(select(.value.Date|contains("9 Jul 2016")))' < ComfySpy_bot_memory.json
#  jq 'del(.page_titles_cache)' < ComfySpy_bot_memory.json | sponge ComfySpy_bot_memory.json

import argparse, email, hashlib, html, json, re, requests, os, sys
from base64 import b64encode
from collections import defaultdict
from email.header import decode_header
from email.utils import parsedate_to_datetime
from imaplib import IMAP4_SSL
from jinja2 import Environment, FileSystemLoader

THIS_SCRIPT_PARENT_DIR = os.path.dirname(os.path.realpath(__file__))

HEADER_EMAIL_SPLITTER_RE = re.compile(', ?\r?\n?\t?')
HEADER_EMAIL_USER_ADDRESS_RE = re.compile(r'"?(cc:\s*)?([^"]+)"?\s+<(.+)>', re.DOTALL)
HEADER_EMAIL_ADDRESS_RE = re.compile(r'[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}')
CONTENT_LINK_TAGS_RE = re.compile(r'<a .*?href="?(http[^> "]*)"?[^>]*?>([^<]*?)</a>', re.DOTALL)
CATEGORY_HASHTAGS_RE = re.compile(r'(^|\s)#([a-zA-Z][a-zA-Z0-9_]+)(\s|$)')

HISTORY_LINE_PREFIX_RE = re.compile('\r\n>+')
REPEATED_SPACE_RE = re.compile(r'\s+')
ESCAPED_REPEATED_SPACE_RE = re.compile(r'\\\s+')

def main(argv=None):
    args = parse_args(argv)
    archive = load_archive_from_file(args.project_name)
    if not args.rebuild_from_cache_only:
        already_fetched_ids = sum([rawdatum['msg_ids'] for rawdatum in archive['rawdata'].values()], [])
        msgs = imap_get_new_msgs(args.email_subject, already_fetched_ids, args.imap_username, args.imap_password,
                                 args.imap_server_name, args.imap_server_port, args.imap_mailbox)
        archive['rawdata'].update(dedupe_and_index_by_hash(extract_rawdata(msgs)))
        save_archive_to_file(args.project_name, archive) # This first dump to disk ensure we won't have to fetch the server even if the following fails
    emails = extract_emails(archive['rawdata'], args.ignored_links_pattern)
    add_page_titles(archive['page_titles_cache'], emails)
    save_archive_to_file(args.project_name, archive)
    users = aggregate_users(emails)
    fix_usernames(users, args.project_name)
    archive['stats'] = compute_stats(emails)
    archive['mailto_href_base64'] = None
    if not args.exclude_mailto:
        dest = ';'.join(user_email for user_email, user in users.items() if archive['stats']['users'][user['name']]['emails_sent'])
        archive['mailto_href_base64'] = b64encode(('mailto:' + dest + '?subject=' + args.email_subject).encode()).decode()
    archive['links'] = [link for email_msg in emails.values()
                             for link in email_msg['links']]
    generates_html_report(archive, args.project_name)

def parse_args(argv):
    parser = argparse.ArgumentParser(description='Generates an HTML report of all mentioned songs in emails retrieved from IMAP server (e.g. Gmail)',
                                     formatter_class=ArgparseHelpFormatter)
    parser.add_argument('--imap-username', required=True, help='Your Gmail account name')
    parser.add_argument('--imap-password', required=True, help="With Gmail you'll need to generate an app password on https://security.google.com/settings/security/apppasswords")
    parser.add_argument('--email-subject', required=True)
    parser.add_argument('--rebuild-from-cache-only', action='store_true')
    parser.add_argument('--ignored-links-pattern', default=r'www.avast.com|\.gif$|\.jpe?g$', help=' ')
    parser.add_argument('--exclude-mailto', action='store_true', help='So that no email appears in the HTML page')
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
        print(len(msgids), 'matching messages found')
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
    return {id: {
        'Date': msg.get('Date'),
        'From': msg.get('From'),
        'To': msg.get('To'),
        'Cc': msg.get('Cc'),
        'text/html': get_msg_content(msg.get_payload(), 'text/html'),
        'text/plain': get_msg_content(msg.get_payload(), 'text/plain'),
    } for id, msg in email_msgs.items()}

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

def dedupe_and_index_by_hash(rawdata):
    print('Now deduping rawdata (IMAP msgs often change ID, at least on Gmail)')
    rawdata_by_hash = {}
    for msg_id, rawdatum in rawdata.items():
        hash_id = hashlib.md5('|'.join(v or '' for k, v in rawdatum.items() if k != 'msg_ids').encode('utf8')).hexdigest()
        if hash_id not in rawdata_by_hash:
            rawdata_by_hash[hash_id] = rawdatum
            rawdata_by_hash[hash_id]['msg_ids'] = [msg_id]
        else:
            rawdata_by_hash[hash_id]['msg_ids'].append(msg_id)
            print('- duplicates msgs found:', rawdata_by_hash[hash_id]['msg_ids'])
    return rawdata_by_hash

def extract_emails(rawdata, ignored_links_pattern):
    print('Now extracting meaningful info from raw data')
    emails = {}
    for msg_id, rawdatum in rawdata.items():
        email_msg = {'id': msg_id, 'links': []}
        email_msg.update(format_date(rawdatum['Date']))
        email_msg.update(extract_src_dst(rawdatum))
        emails[msg_id] = email_msg
    links = extract_all_links(rawdata, emails, ignored_links_pattern)
    for link in links:
        link['email']['links'].append(link)
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
        user_name = concatenate_repeated_spaces(user_name)
    else:
        user_email = HEADER_EMAIL_ADDRESS_RE.match(address.strip().lower()).group()
        user_name = ''
    return user_email.lower(), user_name

def extract_all_links(rawdata, emails, ignored_links_pattern):
    links_per_url = {}
    for msg_id, rawdatum in rawdata.items():
        extract_links(rawdatum, emails[msg_id], links_per_url, ignored_links_pattern)
    return [link for link in links_per_url.values() if link]

def extract_links(rawdatum, email_msg, links_per_url, ignored_links_pattern):
    for match in re.findall(CONTENT_LINK_TAGS_RE, rawdatum['text/html']):
        url, text = match
        text = text.strip()
        if not text:
            continue
        if url in links_per_url:
            similar_link = links_per_url[url]
            if not similar_link or similar_link['email']['timestamp'] < email_msg['timestamp']:
                continue
        if ignored_links_pattern and re.search(ignored_links_pattern, url):
            print('- Ignoring link {} ({})'.format(text, url))
            links_per_url[url] = False
            continue
        if url.count('http') > 1:  # This handle cases like http://https://www.youtube.com/watch?v=Qt-of-5EwhU
            url = re.search('http(?!.+http).+', url).group()
        text = concatenate_repeated_spaces(text)
        quote, regex = extract_quote(text, url, rawdatum['text/plain'])
        tags = set(extract_tags(quote))
        quote = re.sub(regex, '<a href="{}">{}</a>'.format(url, text), quote)
        for tag in tags:
            quote = re.sub('#'+tag, '<a href="#{0}">#{0}</a>'.format(tag), quote)
        links_per_url[url] = {'url': url, 'quote': quote, 'text': text, 'tags': tags, 'email': email_msg}

def extract_quote(text, url, plain_text_content):
    plain_text_content = re.sub(HISTORY_LINE_PREFIX_RE, '', plain_text_content)
    plain_text_content = re.sub(r'<(?!' + re.escape(url) + r')[^>]+>', '', plain_text_content)
    plain_text_content = re.sub(r'http[^\s]+' + re.escape(url), url, plain_text_content)  # This handle cases like http://https://www.youtube.com/watch?v=Qt-of-5EwhU
    plain_text_content = re.sub(r'(?!' + re.escape(url) + r')http[^\s]+\?[^\s]+', '', plain_text_content)
    if url in text:   # 'in' instead of == to handle cases like http://https://www.youtube.com/watch?v=Qt-of-5EwhU
        regex = re.escape(url)
    else:
        regex = re.sub(ESCAPED_REPEATED_SPACE_RE, r'\s+', re.escape(text)) + r'\s*<' + re.escape(url) + '>'
    match = re.search(r'(^|[.!?]|\n\s*\n)([^.!?](?!\n\s*\n))*?' + regex + r'[^.!?]*?([.!?]|\n\s*\n|$)', plain_text_content, re.DOTALL)
    if not match:
        regex = re.sub(ESCAPED_REPEATED_SPACE_RE, r'\s+', re.escape(text))
        match = re.search(r'(^|[.!?]|\n\s*\n)([^.!?](?!\n\s*\n))*?' + regex + r'[^.!?]*?([.!?]|\n\s*\n|$)', plain_text_content, re.DOTALL)
    quote = match.group().strip()
    if quote[0] in '.!?':
        quote = quote[1:]
    return concatenate_repeated_spaces(quote.strip()), regex

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
    if not match:
        return ''
    return match.group(1)

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

def generates_html_report(archive, project_name):
    print('Now generating the HTML report')
    env = Environment(loader=FileSystemLoader(THIS_SCRIPT_PARENT_DIR))
    #env.filters['format_date'] = jinja_format_date
    template = env.get_template('music_emails_spybot_report_template.html')
    html_report_path = os.path.join(THIS_SCRIPT_PARENT_DIR, project_name + '.html')
    with open(html_report_path, 'w') as report_file:
        report_file.write(template.render(project_name=project_name, **archive))

def concatenate_repeated_spaces(text):
    return re.sub(REPEATED_SPACE_RE, ' ', text)

if __name__ == '__main__':
    main()
