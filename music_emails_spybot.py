#!/usr/bin/env python3

# Useful commands:
#  jq 'with_entries(select(.value.Date|contains("9 Jul 2016")))' < ComfySpy_rawdata.json
#  jq 'del(.ce359021b4e0341745472c29441271bb.links[1])' ComfySpy_emails.json | sponge ComfySpy_emails.json
#  jq 'with_entries(select(.value.msg_ids[]|contains("18205")))' < ComfySpy_rawdata.json

import argparse, email, hashlib, html, json, re, requests, os, sys
from base64 import b64encode
from collections import Counter, defaultdict
from email.header import decode_header
from email.utils import parsedate_to_datetime
from imaplib import IMAP4_SSL
from urllib.parse import urlparse

from jinja2 import Environment, FileSystemLoader

THIS_SCRIPT_PARENT_DIR = os.path.dirname(os.path.realpath(__file__))

HEADER_EMAIL_USER_ADDRESS_RE = re.compile(r'"?\\?"?(cc:\s*)?([^"]+)"?\\?"?\s+<(.+)>', re.DOTALL)
HEADER_EMAIL_ML_USER_ADDRESS_RE = re.compile(r'"(.+)" \(.+\)')
HEADER_EMAIL_ADDRESS_RE = re.compile(r'<?([a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})>?')
CONTENT_LINK_TAGS_RE = re.compile(r'<a .*?href="?(http[^> "]*)"?[^>]*?>([^<]*?)</a>', re.DOTALL)
CATEGORY_HASHTAGS_RE = re.compile(r'(^|\s)#([a-zA-Z][a-zA-Z0-9_]+)(\s|$)')

HISTORY_LINE_PREFIX_RE = re.compile('\r\n>+')
REPEATED_SPACE_RE = re.compile(r'\s+')
ESCAPED_REPEATED_SPACE_RE = re.compile(r'\\\s+')

def main(argv=None):
    args = parse_args(argv)
    emails = retrieve_emails(args)
    add_page_titles(args.project_name, emails)
    users = aggregate_users_in_emails(emails)
    fix_usernames(users, args.project_name)
    archive = {}
    archive['links'] = [link for email_msg in emails.values()
                             for link in email_msg['links']]
    archive['youtube_stats'] = compute_youtube_stats(archive['links'], args.youtube_api_key) if args.youtube_api_key else {}
    archive['email_stats'] = compute_email_stats(emails) if args.render_email_stats else {}
    archive['mailto_href_base64'] = None
    if archive['email_stats'] and not args.no_mailto:
        dest = ';'.join(user_email for user_email, user in users.items() if archive['email_stats']['users'][user['name']]['emails_sent'])
        archive['mailto_href_base64'] = b64encode(('mailto:' + dest + '?subject=' + (args.email_subject or args.project_name)).encode()).decode()
    generates_html_report(archive, args.project_name)

def parse_args(argv):
    parser = argparse.ArgumentParser(description='Generates an HTML report of all mentioned songs in emails retrieved from IMAP server (e.g. Gmail)',
                                     formatter_class=ArgparseHelpFormatter)
    parser.add_argument('--imap-username', required=True, help='Your Gmail account name')
    parser.add_argument('--imap-password', required=True, help="With Gmail you'll need to generate an app password on https://security.google.com/settings/security/apppasswords")
    parser.add_argument('--email-subject', required=False)
    parser.add_argument('--email-src', required=False)
    parser.add_argument('--email-dest', required=False)
    parser.add_argument('--rebuild-from-cache-only', action='store_true', help='Do not perform any IMAP connection')
    parser.add_argument('--rebuild-emails-cache', action='store_true', help='Re-parse all IMAP raw data')
    parser.add_argument('--imap-mailbox', default='"[Gmail]/Tous les messages"', help=' ')
    parser.add_argument('--imap-server-name', default='imap.gmail.com', help=' ')
    parser.add_argument('--imap-server-port', type=int, default=993, help=' ')
    parser.add_argument('--ignored-links-pattern', default=r'www.avast.com|framalistes.org|\.gif$|\.jpe?g$|\.img$', help=' ')
    parser.add_argument('--only-links-pattern', help=' ')
    parser.add_argument('--only-from-emails', help=' ')
    parser.add_argument('--youtube-api-key', help='If set, includes at the bottom some stats on Youtube songs classification')
    parser.add_argument('--no-email-stats', dest='render_email_stats', default=True, action='store_false', help=' ')
    parser.add_argument('--no-mailto', action='store_true', help='So that no email appears in the HTML page')
    parser.add_argument('project_name')
    args = parser.parse_args(argv)
    if not args.email_subject and not args.email_dest:
        parser.error('--email-subject or --email-dest required')
    return args

class ArgparseHelpFormatter(argparse.RawTextHelpFormatter, argparse.ArgumentDefaultsHelpFormatter):
    pass

def retrieve_emails(args):
    print('Now loading emails from on-disk cache file')
    emails = load_json_file(args.project_name, 'emails')
    if not args.rebuild_from_cache_only:
        new_rawdata = retrieve_rawdata(args)
        new_emails = extract_emails(new_rawdata, args)
        emails.update(new_emails)
        dedupe_links(emails)
        save_json_file(emails, args.project_name, 'emails')
    # We cross-reference parent emails in links AFTER writing the cache to avoid circular references
    for email_msg in emails.values():
        for link in email_msg['links']:
            link['email'] = email_msg
    return emails

def retrieve_rawdata(args):
    print('Now loading rawdata from on-disk cache file')
    rawdata = load_json_file(args.project_name, 'rawdata')
    already_fetched_ids = frozenset(sum([rawdatum['msg_ids'] for rawdatum in rawdata.values()], []))
    new_msgs = imap_get_new_msgs(args, already_fetched_ids)
    new_rawdata = dedupe_and_index_by_hash(extract_rawdata(new_msgs))
    rawdata.update(new_rawdata)
    save_json_file(rawdata, args.project_name, 'rawdata')
    return rawdata if args.rebuild_emails_cache else new_rawdata

def imap_get_new_msgs(args, already_fetched_ids):
    imap = IMAP4_SSL(args.imap_server_name, args.imap_server_port)
    try:
        return_code, msgids = imap.login(args.imap_username, args.imap_password)
        assert msgids[0].endswith(b' authenticated (Success)') and return_code == 'OK'
        return_code, msgids = imap.select(mailbox=args.imap_mailbox, readonly=True)
        assert return_code == 'OK'
        msgids = set()
        if args.email_subject:
            print('Now searching for messages in {} matching subject "{}"'.format(args.imap_mailbox, args.email_subject))
            matching_msgids = imap_search(imap, 'SUBJECT', args.email_subject)
            print(len(matching_msgids), 'matching messages found')
            msgids.update(set(matching_msgids) - already_fetched_ids)
        if args.email_src:
            print('Now searching for messages in {} width src "{}"'.format(args.imap_mailbox, args.email_src))
            matching_msgids = imap_search(imap, 'FROM', args.email_src)
            print(len(matching_msgids), 'matching messages found')
            msgids.update(set(matching_msgids) - already_fetched_ids)
        if args.email_dest:
            print('Now searching for messages in {} width dest "{}"'.format(args.imap_mailbox, args.email_dest))
            matching_msgids = imap_search(imap, 'TO', args.email_dest)
            print(len(matching_msgids), 'matching messages found')
            msgids.update(set(matching_msgids) - already_fetched_ids)
        print('Now fetching {} new messages'.format(len(msgids)))
        msgs = {id: imap.fetch(id.encode('ascii'), '(RFC822)') for id in msgids}
        assert all(msg[0] == 'OK' for msg in msgs.values())
        return msgs
    finally:
        imap.logout()

def imap_search(imap, *args):
    return_code, msgids = imap.search(None, *args)
    assert return_code == 'OK' and len(msgids) == 1
    return msgids[0].decode('ascii').split(' ')

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
    return None

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

def extract_emails(new_rawdata, args):
    print('Now extracting meaningful info from raw data')
    new_emails = {}
    for i, (msg_id, rawdatum) in enumerate(new_rawdata.items()):
        email_msg = {'id': msg_id, 'links': []}
        email_msg.update(format_date(rawdatum['Date']))
        email_msg.update(extract_src_dst(rawdatum))
        new_emails[msg_id] = email_msg
        email_src = list(email_msg['src'].keys())[0]
        if args.only_from_emails and not re.search(args.only_from_emails, email_src):
            print('- Ignoring email from {}'.format(email_src))
            continue
        if not rawdatum['text/html']:
            print('- Ignoring email that has no available text/html content')
            continue
        email_msg['links'] = list(extract_links(rawdatum, args))
        print('# LINKS EXTRACTION PROGRESS: {}/{} of all rawdatum done'.format(i + 1, len(new_rawdata)))
    return new_emails

def format_date(date):
    dt = parsedate_to_datetime(date)
    return {'timestamp': dt.timestamp(), 'date_str': dt.strftime('%Y-%m-%d %H:%M')}

def extract_src_dst(rawdatum):
    src_user_email, src_user_name = extract_user_email_and_name(rawdatum['From'])
    dests = []
    if rawdatum.get('To'):
        dests.extend(comma_splitter(html.unescape(rawdatum['To'])))
    if rawdatum.get('Cc'):
        dests.extend(comma_splitter(html.unescape(rawdatum['Cc'])))
    return {'src': {src_user_email: {'name': src_user_name}},  # only one item in there
            'dests': {email: {'name': name} for email, name in (extract_user_email_and_name(dest) for dest in dests)}}

def comma_splitter(email_dests_string):
    start = 0
    in_quotes = False
    for i, c in enumerate(email_dests_string):
        if c == '"':
            in_quotes = not in_quotes
        elif c == ',' and not in_quotes:
            yield email_dests_string[start:i].strip()
            start = i + 1
    yield email_dests_string[start:].strip()

def extract_user_email_and_name(address):
    'Return (user_email, user_name) : the 2nd value only is assured to be non-empty'
    address = address.strip().lower()
    if not address:
        raise ValueError('Empty From/To/Cc email address: {}'.format(address))
    match = HEADER_EMAIL_USER_ADDRESS_RE.match(address)
    if match:
        user_name_label, user_email = match.group(2, 3)
        return user_email.lower(), concatenate_repeated_spaces(decode_email_user_label(user_name_label))
    match = HEADER_EMAIL_ML_USER_ADDRESS_RE.match(address)
    if match:
        user_name = match.group(1).lower()
        return user_name, user_name  # returning user_name as user_email in order for `fix_usernames` to be usable
    match = HEADER_EMAIL_ADDRESS_RE.match(address)
    if match:
        user_email = match.group(1).lower()
        return user_email, user_email
    print('Could not parse email address in From/To/Cc field: {}'.format(address), file=sys.stderr)  # warn
    return '', address

def decode_email_user_label(user_name_label):
    user_name = ''
    for fragment, charset in decode_header(user_name_label):
        try:
            user_name += fragment.decode(charset or 'ascii') if isinstance(fragment, bytes) else fragment
        except UnicodeDecodeError:
            if charset.lower().replace('-', '') != 'utf8':
                raise
            # decoding as UTF8 failed, attempting another well-known charset
            user_name += fragment.decode('latin1')
    return user_name

def extract_links(rawdatum, args):
    # With old msgs in the thread being quoted at the bottom of emails,
    # some are > 250 000 characters.
    # Based on experimental testing, no email is >5000 characters,
    # so we truncate content at this length
    html_content = rawdatum['text/html'][:5000]
    plain_content = rawdatum['text/plain'][:5000]
    for match in re.findall(CONTENT_LINK_TAGS_RE, html_content):
        url, text = match
        text = text.strip()
        if not text:
            print('- Ignoring link with empty text: {}'.format(url))
            continue
        ignore_link = False
        if args.only_links_pattern:
            ignore_link = not re.search(args.only_links_pattern, url)
        elif args.ignored_links_pattern:
            ignore_link = re.search(args.ignored_links_pattern, url)
        if ignore_link:
            print('- Ignoring link matching --only/--ignored pattern: {} ({})'.format(text, url))
            continue
        if url.count('http') > 1:  # This handle cases like http://https://www.youtube.com/watch?v=Qt-of-5EwhU
            url = re.search('http(?!.+http).+', url).group()
        text = concatenate_repeated_spaces(text)
        quote, regex = extract_quote(text, url, plain_content)
        tags = list(extract_tags(quote))
        quote = re.sub(regex, '<a href="{}">{}</a>'.format(url, text), quote)
        for tag in tags:
            quote = re.sub('#'+tag, '<a href="#{0}">#{0}</a>'.format(tag), quote)
        yield {'url': url, 'quote': quote, 'text': text, 'tags': tags}

def extract_quote(text, url, plain_text_content):
    plain_text_content = re.sub(HISTORY_LINE_PREFIX_RE, '', plain_text_content)
    plain_text_content = re.sub(r'<(?!' + re.escape(url) + r')[^>]+>', '', plain_text_content)
    plain_text_content = re.sub(r'http[^\s]+' + re.escape(url), url, plain_text_content)  # This handle cases like http://https://www.youtube.com/watch?v=Qt-of-5EwhU
    plain_text_content = re.sub(r'(?!' + re.escape(url) + r')http[^\s]+\?[^\s]+', '', plain_text_content)
    perform_search = lambda regex: (re.search(r'(^|[.!?]|\n\s*\n)([^.!?](?!\n\s*\n))*?' + regex + r'[^.!?]*?([.!?]|\n\s*\n|$)', plain_text_content, re.DOTALL), regex)
    # First, we look for Confluence wiki-style links: [ text | URL ]
    # (note: based on minimal benchmarking, this is the most expensive of the regexs used)
    match, regex = perform_search(r'\[\s*' + re.sub(ESCAPED_REPEATED_SPACE_RE, r'\s+', re.escape(text)) + r'\s*|\s*' + re.escape(url) + r'\s*\]')
    if not match and url in text:
        # Second, we look for the bare URL if the link text contains it
        # We use 'in' instead of == to handle cases like http://https://www.youtube.com/watch?v=Qt-of-5EwhU
        match, regex = perform_search(re.escape(url))
    if not match:
        # Third, we look for a surrounding sentence containing the link URL, in the form of: text <URL>
        match, regex = perform_search(re.sub(ESCAPED_REPEATED_SPACE_RE, r'\s+', re.escape(text)) + r'\s*<' + re.escape(url) + '>')
    if not match:
        # Fourth, we look for a surrounding sentence containing the link text
        match, regex = perform_search(re.sub(ESCAPED_REPEATED_SPACE_RE, r'\s+', re.escape(text)))
    quote = match.group().strip()
    if quote[0] in '.!?':
        quote = quote[1:]
    return concatenate_repeated_spaces(quote.strip()), regex

def extract_tags(quote):
    for match in re.findall(CATEGORY_HASHTAGS_RE, quote):
        yield match[1]

def dedupe_links(emails):
    processed_urls = set()
    for email_msg in sorted(emails.values(), key=lambda msg: msg['timestamp']):
        links_per_url = {link['url']: link for link in email_msg['links']}  # to dedupe duplicate links in a single email
        email_msg['links'] = [link for url, link in links_per_url.items() if url not in processed_urls]
        processed_urls.update(links_per_url.keys())

def add_page_titles(project_name, emails):
    print('Now getting titles of all linked pages')
    page_titles_cache = load_json_file(project_name, 'page_titles_cache')
    for email_msg in emails.values():
        for link in email_msg['links']:
            if link['url'] not in page_titles_cache:
                page_titles_cache[link['url']] = get_page_title(link['url'])
            link['page_title'] = page_titles_cache[link['url']]
    save_json_file(page_titles_cache, project_name, 'page_titles_cache')

def get_page_title(url):
    try:
        response = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'})
        response.raise_for_status()
    except requests.exceptions.RequestException as error:
        return 'ERROR: {}'.format(error)
    match = re.search('<title>([^<]+)</title>', response.text)
    if not match:
        return 'ERROR: NO TITLE'
    return match.group(1)

def aggregate_users_in_emails(emails):
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
    correct_usernames = load_json_file(project_name, 'imap_usernames')
    if not correct_usernames:
        return
    print('Now fixing the users names')
    for user_email, user in users.items():
        if user_email in correct_usernames:
            user['name'] = correct_usernames[user_email]

def load_json_file(project_name, role):
    json_filepath = os.path.join(THIS_SCRIPT_PARENT_DIR, '{}_{}.json'.format(project_name, role))
    try:
        with open(json_filepath, 'r') as json_file:
            return json.load(json_file)
    except (FileNotFoundError, ValueError):
        return {}

def save_json_file(data, project_name, role):
    json_filepath = os.path.join(THIS_SCRIPT_PARENT_DIR, '{}_{}.json'.format(project_name, role))
    with open(json_filepath, 'w') as json_file:
        json.dump(data, json_file)

def compute_youtube_stats(links, youtube_api_key):
    print('Now computing statistics on Youtube songs topics')
    youtube_video_ids = list(extract_youtube_video_ids([link['url'] for link in links]))
    print('({} youtube video IDs found)'.format(len(youtube_video_ids)))
    video_topics_per_id = get_youtube_videos_topics(youtube_api_key, youtube_video_ids)
    return Counter(sum(video_topics_per_id.values(), []))

def extract_youtube_video_ids(urls):
    for url in urls:
        parsed_url = urlparse(url)
        if parsed_url.hostname == 'youtu.be':
            yield parsed_url.path[1:]
        elif parsed_url.hostname == 'www.youtube.com':
            yield parsed_url.query[2:13]

def get_youtube_videos_topics(youtube_api_key, video_ids, videos_details_request_batch_size=50):
    video_topics_per_id = {}
    batch_start_index = 0
    while batch_start_index < len(video_ids):
        videos_ids_batch = video_ids[batch_start_index:batch_start_index + videos_details_request_batch_size]
        response = requests.get('https://www.googleapis.com/youtube/v3/videos', params={
            'key': youtube_api_key,
            'id': ','.join(videos_ids_batch),  # it is not clearly documented, but the API does not accept more than 50 ids here
            'maxResults': videos_details_request_batch_size,
            'part': 'topicDetails', # cf. https://developers.google.com/youtube/v3/docs/videos/list#parameters
        }).json()
        for item in response['items']:
            video_topics_per_id[item['id']] = [cat.replace('https://en.wikipedia.org/wiki/', '') for cat in item['topicDetails']['topicCategories']] if 'topicDetails' in item else []
        batch_start_index += videos_details_request_batch_size
    return video_topics_per_id

def compute_email_stats(emails):
    print('Now computing statistics on emails sent')
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
