#!/usr/bin/env python3

# Useful commands:
#  jq 'with_entries(select(.value.date_str|contains("2019-04-03")))' < ComfySpy_emails.json
#  jq 'with_entries(select(.value.Date|contains("9 Jul 2016")))' < ComfySpy_rawdata.json
#  jq 'del(.ce359021b4e0341745472c29441271bb.links[1])' ComfySpy_emails.json | sponge ComfySpy_emails.json
#  jq 'with_entries(select(.value.msg_ids[]|contains("18205")))' < ComfySpy_rawdata.json

import argparse, hashlib, html, json, re, requests, os, sys
from base64 import urlsafe_b64decode, b64encode
from collections import Counter, defaultdict
from email.header import decode_header
from email.utils import parsedate_to_datetime
from urllib.parse import urlencode, urlparse, parse_qs

from jinja2 import Environment, FileSystemLoader
try:  # optional dependency
    from tqdm import tqdm
except ImportError:
    tqdm = lambda _: _

THIS_SCRIPT_PARENT_DIR = os.path.dirname(os.path.realpath(__file__))

HEADER_EMAIL_USER_ADDRESS_RE = re.compile(r'"?\\?"?(cc:\s*)?([^"]+)"?\\?"?\s+<(.+)>', re.DOTALL)
HEADER_EMAIL_ML_USER_ADDRESS_RE = re.compile(r'"(.+)" \(.+\)')
HEADER_EMAIL_ADDRESS_RE = re.compile(r'<?([a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})>?')
HTML_CONTENT_LINK_TAGS_RE = re.compile(r'<a .*?href="?(http[^,> "]+)"?[^>]*?>([^<]*?)</a>', re.DOTALL)
PLAIN_CONTENT_LINK_TAGS_RE = re.compile(r'(?:^|\s)(http[^,> "]+?)(?:\s|$)')
CATEGORY_HASHTAGS_RE = re.compile(r'(^|\s)#([a-zA-Z][a-zA-Z0-9_]+)(\s|$)')

HISTORY_LINE_PREFIX_RE = re.compile('\r\n>+')
REPEATED_SPACE_RE = re.compile(r'\s+')
SENTENCE_SPLITTER_RE = re.compile(r'\.\s|!\s|\?\s|\n')

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
    if archive['email_stats'] and args.include_mailto:
        dest = ';'.join(user_email for user_email, user in users.items() if archive['email_stats']['users'][user['name']]['emails_sent'])
        archive['mailto_href_base64'] = b64encode(('mailto:' + dest + '?subject=' + (args.email_subject or args.project_name)).encode()).decode()
    generates_html_report(archive, args)

def parse_args(argv):
    parser = argparse.ArgumentParser(description='Generates an HTML report of all mentioned songs in emails retrieved from Gmail',
                                     formatter_class=ArgparseHelpFormatter)
    parser.add_argument('--email-subject')
    parser.add_argument('--ignored-email-subjects', help='Regular expression')
    parser.add_argument('--email-src', help=' ')
    parser.add_argument('--email-srcs', default=[], type=lambda srcs: srcs.split(','), help='Comma-separated list')
    parser.add_argument('--email-dest', help=' ')
    parser.add_argument('--email-dests', default=[], type=lambda dests: dests.split(','), help='Comma-separated list')
    parser.add_argument('--rebuild-from-cache-only', action='store_true', help='Do not perform any connection to the GMail api, base everything on the "emails" cache file')
    parser.add_argument('--rebuild-rawdata-cache', action='store_true', help='Re-fetch & parse all emails')
    parser.add_argument('--rebuild-emails-cache', action='store_true', help='Re-parse all raw data')
    parser.add_argument('--ignored-links-pattern', default=r'www.avast.com|fbcdn.net|framalistes.org|itch.io|media.spacial.com|www.y/|www.yout/|\.gif$|\.jpe?g$|\.img$', help=' ')
    parser.add_argument('--only-links-pattern', help=' ')
    parser.add_argument('--only-from-emails', help=' ')
    parser.add_argument('--youtube-api-key', help='If set, includes at the bottom some stats on Youtube songs classification')
    parser.add_argument('--description', default='Une archive des morceaux de musique que nous avons échangé par email.', help=' ')
    parser.add_argument('--no-email-stats', action='store_false', dest='render_email_stats', help=' ')
    parser.add_argument('--no-mailto', action='store_false', dest='include_mailto', help='So that no email appears in the HTML page')
    parser.add_argument('--no-robots', action='store_const', dest='robots', const='noindex', help=' ')
    parser.add_argument('project_name')
    args = parser.parse_args(argv)
    if not args.email_subject and not args.email_dest and not args.email_dests:
        parser.error('--email-subject or --email-dest(s) required')
    if args.email_src:
        if args.email_srcs:
            parser.error('Only one of --email-src and --email-srcs must be provided')
        args.email_srcs = [args.email_src]
    if args.email_dest:
        if args.email_dests:
            parser.error('Only one of --email-dest and --email-dests must be provided')
        args.email_dests = [args.email_dest]
    return args

class ArgparseHelpFormatter(argparse.RawTextHelpFormatter, argparse.ArgumentDefaultsHelpFormatter):
    pass

def retrieve_emails(args):
    print('Now loading emails from on-disk cache file')
    emails = {} if args.rebuild_emails_cache else load_json_file(args.project_name, 'emails')
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
    if args.rebuild_rawdata_cache:
        rawdata = {}
        already_fetched_ids = frozenset()
    else:
        rawdata = load_json_file(args.project_name, 'rawdata')
        already_fetched_ids = frozenset(sum([rawdatum['msg_ids'] for rawdatum in rawdata.values()], []))
    new_msgs_per_msgid = get_new_email_msgs(args, already_fetched_ids)
    new_rawdata = dedupe_and_index_by_hash(rawdata, extract_rawdata(new_msgs_per_msgid, args.ignored_email_subjects))
    rawdata.update(new_rawdata)
    save_json_file(rawdata, args.project_name, 'rawdata')
    return rawdata if args.rebuild_emails_cache else new_rawdata

def get_new_email_msgs(args, already_fetched_ids):
    with open("token.json", encoding="utf-8") as token_file:
        token = json.load(token_file)
    msgids = set()
    if args.email_subject:
        print(f'Now searching for messages matching subject "{args.email_subject}"')
        matching_msgids = email_search(token, args.email_subject)
        already_fetched_msg_ids = set(matching_msgids) & already_fetched_ids
        print(len(matching_msgids), 'matching messages found -', len(already_fetched_msg_ids), 'are already fetched in cache')
        msgids.update(set(matching_msgids) - already_fetched_msg_ids)
    for email_src in args.email_srcs:
        print(f'Now searching for messages with src "{email_src}"')
        matching_msgids = email_search(token, f"from:{email_src}")
        already_fetched_msg_ids = set(matching_msgids) & already_fetched_ids
        print(len(matching_msgids), 'matching messages found -', len(already_fetched_msg_ids), 'are already fetched in cache')
        msgids.update(set(matching_msgids) - already_fetched_msg_ids)
    for email_dest in args.email_dests:
        print(f'Now searching for messages with dest "{email_dest}"')
        matching_msgids = email_search(token, f"to:{email_dest}")
        already_fetched_msg_ids = set(matching_msgids) & already_fetched_ids
        print(len(matching_msgids), 'matching messages found -', len(already_fetched_msg_ids), 'are already fetched in cache')
        msgids.update(set(matching_msgids) - already_fetched_msg_ids)
    print(f'Now fetching {len(msgids)} new messages')
    return {msg_id: email_get(token, msg_id) for msg_id in tqdm(msgids)}

def email_search(token, query, page_token=''):
    resp = requests.get(f"https://www.googleapis.com/gmail/v1/users/me/messages?maxResults=500&pageToken={page_token}&q={query}", headers={
        "Authorization": f'Bearer {token["access_token"]}'
    })
    resp_data = resp.json()
    if resp.status_code >= 400:
        print(resp_data)
    resp.raise_for_status()
    msgs = [msg["id"] for msg in resp_data["messages"]]
    # Handle pagination of search results:
    next_page_token = resp_data.get("nextPageToken")
    if next_page_token:
        msgs.extend(email_search(token, query, page_token=next_page_token))
    return msgs

def email_get(token, msg_id):
    resp = requests.get(f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{msg_id}", headers={
        "Authorization": f'Bearer {token["access_token"]}'
    })
    resp_data = resp.json()
    if resp.status_code >= 400:
        print(resp_data)
    resp.raise_for_status()
    return resp_data

def extract_rawdata(msgs_per_msgid, ignored_email_subjects):
    "Data model of an email Message: https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages#Message"
    print(f'Now extracting raw data from {len(msgs_per_msgid)} fetched messages')
    compiled_re = re.compile(ignored_email_subjects or '.*')
    rawdata = {}
    for msg_id, msg in msgs_per_msgid.items():
        payload = msg["payload"]
        headers = {header["name"]: header["value"] for header in payload["headers"]}
        email_subject = headers['Subject']
        if ignored_email_subjects and compiled_re.search(email_subject):
            print('- Ignoring email with subject:', email_subject)
            continue
        rawdata[msg_id] = {
            'Date': headers['Date'],
            'From': headers.get('Reply-To') or headers['From'],
            'To': headers.get('To'),
            'Subject': email_subject,
            'text/html': get_msg_content(msg, 'text/html'),
            'text/plain': get_msg_content(msg, 'text/plain'),
        }
    return rawdata

def get_msg_content(msg, target_content_type):
    payload = msg["payload"]
    body = payload.get("body")
    if body and body["size"]:
        if payload["mimeType"] != target_content_type:
            return None
    elif payload["mimeType"].startswith("multipart"):
        matching_part = next((part for part in payload["parts"] if part["mimeType"] == target_content_type), None)
        if not matching_part:
            return None
        body = matching_part["body"]
    else:
        return None
    data = body.get("data")
    if not data:
        return None
    return html.unescape(decode_ffs(urlsafe_b64decode(data)))

def decode_ffs(bytestring):  # Decode this bytestring for fuck's sake
    try:
        return bytestring.decode('utf8')
    except UnicodeError:
        return bytestring.decode('latin1')

def dedupe_and_index_by_hash(rawdata, new_rawdata):
    print('Now deduping new rawdata (GMail msgs often change ID)')
    new_rawdata_by_hash = {}
    for msg_id, rawdatum in new_rawdata.items():
        hash_id = hashlib.md5('|'.join(v or '' for k, v in rawdatum.items() if k != 'msg_ids').encode('utf8')).hexdigest()
        existing_rawdatum = rawdata.get(hash_id)
        if existing_rawdatum is not None or hash_id in new_rawdata_by_hash:
            if hash_id not in new_rawdata_by_hash:
                new_rawdata_by_hash[hash_id] = existing_rawdatum
                new_rawdata_by_hash[hash_id]['msg_ids'] = []
                found_where = 'in cached rawdata'
            else:
                found_where = 'among newly fetch'
            new_rawdata_by_hash[hash_id]['msg_ids'].append(msg_id)
            print(f'- duplicate msgs found {found_where}:', rawdata[hash_id]['msg_ids'])
        else:
            new_rawdata_by_hash[hash_id] = rawdatum
            new_rawdata_by_hash[hash_id]['msg_ids'] = [msg_id]
    return new_rawdata_by_hash

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
            print(f'- Ignoring email from {email_src}')
            continue
        email_msg['links'] = extract_links(rawdatum, args)
        print(f'# LINKS EXTRACTION PROGRESS: {i + 1}/{len(new_rawdata)} of all rawdatum done')
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
    address = address.strip()
    if not address:
        raise ValueError(f'Empty From/To/Cc email address: {address}')
    match = HEADER_EMAIL_USER_ADDRESS_RE.match(address)
    if match:
        user_name_label, user_email = match.group(2, 3)
        return user_email.lower(), concatenate_repeated_spaces(decode_email_user_label(user_name_label)).lower()
    match = HEADER_EMAIL_ML_USER_ADDRESS_RE.match(address)
    if match:
        user_name = match.group(1).lower()
        return user_name, user_name  # returning user_name as user_email in order for `fix_usernames` to be usable
    match = HEADER_EMAIL_ADDRESS_RE.match(address)
    if match:
        user_email = match.group(1).lower()
        return user_email, user_email
    print(f'Could not parse email address in From/To/Cc field: {address}', file=sys.stderr)  # warn
    return '', address.lower()

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
    plain_content = rawdatum.get('text/plain') or rawdatum['text/html']
    if not plain_content:
        return []
    # With old msgs in the thread being quoted at the bottom of emails,
    # some are > 250 000 characters.
    # Based on experimental testing, no email is >5000 characters,
    # so we truncate content at this length
    plain_content = plain_content[:5000]
    html_content = (rawdatum.get('text/html') or '')[:5000].replace('<wbr>', '')
    # Note: ici la troncature est rarement faite au même niveau dans les 2 versions
    # (la version HTML pouvant être 3x + longue que la version TEXT pour un même contenu)
    # ce qui peut entrainer des soucis de dé-duplication de liens malformés n'apparaissant que dans la version TEXT.
    # On pourrait donc essayer d'être + intelligents pour faire matcher ces 2 variables *_content
    links_per_url = {}
    for match in re.findall(HTML_CONTENT_LINK_TAGS_RE, html_content):
        url, text = match
        text = text.strip()
        if not text:
            print(f'- Ignoring link with empty text: {url}')
            continue
        link = extract_quote_and_tags(args, url, plain_content, text)
        if link:
            links_per_url[url] = link
    for url in re.findall(PLAIN_CONTENT_LINK_TAGS_RE, plain_content):
        url = url.strip()
        if any(url.startswith(already_extracted_url) or already_extracted_url.startswith(url) for already_extracted_url in links_per_url):
            continue
        link = extract_quote_and_tags(args, url, plain_content)
        if link:
            links_per_url[url] = link
    return links_per_url.values()

def extract_quote_and_tags(args, url, plain_content, text=''):
    url = clean_up_url(url)
    if not url:
        return None
    if args.ignored_links_pattern and re.search(args.ignored_links_pattern, url):
        print(f'- Ignoring link matching --ignored pattern: {text} ({url})')
        return None
    if args.only_links_pattern and not re.search(args.only_links_pattern, url):
        print(f'- Ignoring link not matching --only pattern: {text} ({url})')
        return None
    if text:
        quote, regex = extract_quote_with_text(concatenate_repeated_spaces(text), url, plain_content)
        if quote:
            quote = re.sub(regex, f'<a href="{url}">{text}</a>', quote)
        else:
            quote = f'<a href="{url}">{text}</a>'
    else:
        quote = extract_quote(url, plain_content)
        if quote:
            quote = f'<a href="{url}">{quote}</a>'
        else:
            quote = f'<a href="{url}">{url}</a>'
    tags = list(extract_tags(quote))
    for tag in tags:
        quote = re.sub('#'+tag, f'<a href="#{tag}">#{tag}</a>', quote)
    quote = re.sub('  +', ' ', quote.replace('\n', '').replace('\r', '').replace('\t', ''))
    text = re.sub('  +', ' ', text.replace('\n', '').replace('\r', '').replace('\t', ''))
    return {'url': url, 'quote': quote, 'text': text, 'tags': tags}

def clean_up_url(url):
    if url.count('http') > 1:  # This handle cases like http://https://www.youtube.com/watch?v=Qt-of-5EwhU
        url = re.search('http(?!.+http).+', url).group()
    parsed_url = urlparse(url)
    if parsed_url.hostname == 'www.youtube.com' and parsed_url.path != '/watch':
        return None  # invalid Youtube URL
    query_params = parse_qs(parsed_url.query)
    if 'v' in query_params and len(query_params['v'][0]) != 11:
        return None  # invalid Youtube URL
    if 'index' in query_params:
        del query_params['index']  # Youtube
    if 'list' in query_params:
        del query_params['list']  # Youtube
    if 't' in query_params:
        del query_params['t']  # Youtube
    return parsed_url._replace(query=urlencode(query_params, doseq=True)).geturl()

def extract_quote_with_text(text, url, plain_text_content):
    plain_text_content = re.sub(HISTORY_LINE_PREFIX_RE, '', plain_text_content)
    plain_text_content = re.sub(r'<(?!' + re.escape(url) + r')[^>]+>', '', plain_text_content)
    plain_text_content = re.sub(r'http[^\s]+' + re.escape(url), url, plain_text_content)  # This handle cases like http://https://www.youtube.com/watch?v=Qt-of-5EwhU
    plain_text_content = re.sub(r'(?!' + re.escape(url) + r')http[^\s]+\?[^\s]+', '', plain_text_content)
    def perform_search(regex):
        return re.search(r'(^|[.!?]|\n\s*\n)([^.!?](?!\n\s*\n))*?' + regex + r'[^.!?]*?([.!?]|\n\s*\n|$)', plain_text_content, re.DOTALL), regex
    escaped_text = re.escape(text)
    # First, we look for Confluence wiki-style links: [ text | URL ]
    # (note: based on minimal benchmarking, this is the most expensive of the regexs used)
    match, regex = perform_search(r'\[\s*' + escaped_text + r'\s*|\s*' + re.escape(url) + r'\s*\]')
    if not match and url in text:
        # Second, we look for the bare URL if the link text contains it
        # We use 'in' instead of == to handle cases like http://https://www.youtube.com/watch?v=Qt-of-5EwhU
        match, regex = perform_search(re.escape(url))
    if not match:
        # Third, we look for a surrounding sentence containing the link URL, in the form of: text <URL>
        match, regex = perform_search(escaped_text + r'\s*<' + re.escape(url) + '>')
    if not match:
        # Fourth, we look for a surrounding sentence containing the link text
        match, regex = perform_search(escaped_text)
    if not match:
        return None, None
    quote = match.group().strip()
    if quote and quote[0] in '.!?':
        quote = quote[1:]
    return concatenate_repeated_spaces(quote), regex

def extract_quote(url, plain_text_content):
    plain_text_content = re.sub(HISTORY_LINE_PREFIX_RE, '', plain_text_content)
    sentences = [s.strip() for s in re.split(SENTENCE_SPLITTER_RE, plain_text_content)]
    try:
        i = next(i for i, s in enumerate(sentences) if url in s)
    except StopIteration:
        return None
    for i in range(i, -1, -1):
        quote = re.sub(PLAIN_CONTENT_LINK_TAGS_RE, '', sentences[i]).strip()
        if quote:
            return quote
    return None

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
                page_title = get_page_title(link['url'])
                page_titles_cache[link['url']] = page_title
                print(f'* new page title retrieved: {page_title}')
            link['page_title'] = page_titles_cache[link['url']]
    save_json_file(page_titles_cache, project_name, 'page_titles_cache')

def get_page_title(url):
    try:
        response = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'})
        response.raise_for_status()
    except requests.exceptions.RequestException as error:
        return f'ERROR: {error}'
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
    correct_usernames = load_json_file(project_name, 'username_aliases')
    if not correct_usernames:
        return
    print('Now fixing the users names')
    for user_email, user in users.items():
        if user_email in correct_usernames:
            user['name'] = correct_usernames[user_email]

def load_json_file(project_name, role):
    try:
        with open(f'{project_name}_{role}.json', 'r', encoding='utf-8') as json_file:
            return json.load(json_file)
    except (FileNotFoundError, ValueError) as error:
        print(f"WARN: {error}")
        return {}

def save_json_file(data, project_name, role):
    with open(f'{project_name}_{role}.json', 'w', encoding='utf-8') as json_file:
        json.dump(data, json_file, indent=2)

def compute_youtube_stats(links, youtube_api_key):
    print('Now computing statistics on Youtube songs topics')
    youtube_video_ids = list(extract_youtube_video_ids([link['url'] for link in links]))
    print(f'({len(youtube_video_ids)} youtube video IDs found)')
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

def generates_html_report(archive, args):
    print('Now generating the HTML report')
    env = Environment(loader=FileSystemLoader(THIS_SCRIPT_PARENT_DIR))
    #env.filters['format_date'] = jinja_format_date
    template = env.get_template('music_emails_spybot_report_template.html')
    with open(f'{args.project_name}.html', 'w', encoding='utf-8') as report_file:
        report_file.write(template.render(project_name=args.project_name, robots=args.robots, description=args.description, **archive))

def concatenate_repeated_spaces(text):
    return re.sub(REPEATED_SPACE_RE, ' ', text)

if __name__ == '__main__':
    main()
