from argparse import Namespace
from quopri import decodestring as email_decode  # quoted-printable encoding

from music_emails_spybot import extract_links, extract_quote, extract_src_dst, extract_user_email_and_name


ARGS_NO_PATTERNS = Namespace(ignored_links_pattern=None, only_links_pattern=None)


def test_tags_extraction():
    rawdatum = {
        'text/html': '<div dir="ltr">Merci :)<br>Bwarf, j\'ai pas trop envie de paginer franchement.<br><br>Allez zou, un petit morceau de #pop qui rend #happy : <a href="https://www.youtube.com/watch?v=uJ_1HMAGb4k">https://www.youtube.com/watch?v=uJ_1HMAGb4k</a></div>',
        'text/plain': 'Merci :)\r\nBwarf, j\'ai pas trop envie de paginer franchement.\r\n\r\nAllez zou, un petit morceau de #pop qui rend #happy :\r\nhttps://www.youtube.com/watch?v=uJ_1HMAGb4k\r\n\r\n',
    }
    links = list(extract_links(rawdatum, args=ARGS_NO_PATTERNS))
    links_per_url = {link['url']: link for link in links}
    assert links_per_url['https://www.youtube.com/watch?v=uJ_1HMAGb4k']['quote'] == 'Allez zou, un petit morceau de <a href="#pop">#pop</a> qui rend <a href="#happy">#happy</a> : <a href="https://www.youtube.com/watch?v=uJ_1HMAGb4k">https://www.youtube.com/watch?v=uJ_1HMAGb4k</a>'


def test_multiple_links_with_same_quote():
    rawdatum = {
        'text/html': 'Je ne vais pas trop m’étendre étant donné que je n\'est bien exploré que leur dernier album pour le moment (<a href="https://i.ytimg.com/vi/4-FTRHflHFs/maxresdefault.jpg">Cooking with pagans</a>), mais c\'est du <a href="https://www.youtube.com/watch?v=y9ytbURTs40">Hard Rock</a>, <a href="https://www.youtube.com/watch?v=tRx8AAht9jY">Heavy Metal</a>, <a href="https://www.youtube.com/watch?v=30bQJuKbN3E">Progressive Metal</a> bien barré (mention spéciale pour "<a href="https://www.youtube.com/watch?v=qoSpzbE31KA">Anal bleach</a>" et toute la poésie qui se dégage du titre).',
        'text/plain': 'Je ne vais pas trop m’étendre étant donné que je n\'est bien exploré que\r\nleur dernier album pour le moment (Cooking with pagans\r\n<https://i.ytimg.com/vi/4-FTRHflHFs/maxresdefault.jpg>), mais c\'est du Hard\r\nRock <https://www.youtube.com/watch?v=y9ytbURTs40>, Heavy Metal\r\n<https://www.youtube.com/watch?v=tRx8AAht9jY>, Progressive Metal\r\n<https://www.youtube.com/watch?v=30bQJuKbN3E> bien barré (mention spéciale\r\npour "Anal bleach <https://www.youtube.com/watch?v=qoSpzbE31KA>" et toute\r\nla poésie qui se dégage du titre).',
    }
    links = list(extract_links(rawdatum, args=ARGS_NO_PATTERNS))
    assert len(links) == 5  # 4 Youtube links + 1 jpg
    assert all(link['quote'].count('<a href=') == 1 for link in links)


def test_workaround_typo():
    rawdatum = {
        'text/html': '<div><a href="http://https://www.youtube.com/watch?v=Qt-of-5EwhU">http://https://www.youtube.com/watch?v=Qt-of-5EwhU</a><br><br><div>',
        'text/plain': '\r\nhttp://https://www.youtube.com/watch?v=Qt-of-5EwhU\r\n\r\n',
    }
    links = list(extract_links(rawdatum, args=ARGS_NO_PATTERNS))
    links_per_url = {link['url']: link for link in links}
    assert links_per_url['https://www.youtube.com/watch?v=Qt-of-5EwhU']['quote'] == '<a href="https://www.youtube.com/watch?v=Qt-of-5EwhU">http://https://www.youtube.com/watch?v=Qt-of-5EwhU</a>'


def test_gmail_styled_hrefs_extraction():
    rawdatum = {
        'text/html': "<div dir=\"ltr\">Petit partage à mon tour, pour vous faire découvrir Cabadzi !<div><a href=\"https://www.youtube.com/watch?v=YnEBdT75RUQ\">https://www.youtube.com/watch?v=YnEBdT75RUQ</a></div><div><a class=\"gmail-_553k\" href=\"https://www.youtube.com/watch?v=42-Xq5VYrLE\" target=\"_blank\" rel=\"nofollow\" style=\"font-size:13px;color:rgb(54,88,153);text-decoration:none;font-family:helvetica,arial,sans-serif;line-height:17.94px;white-space:pre-wrap\">https://www.youtube.com/watch?v=42-Xq5VYrLE</a><br></div><div><a class=\"gmail-_553k\" href=\"https://www.youtube.com/watch?v=IHpR0sP5xXo\" target=\"_blank\" rel=\"nofollow\" style=\"color:rgb(54,88,153);text-decoration:none;font-family:helvetica,arial,sans-serif;font-size:13px;line-height:17.94px;white-space:pre-wrap\">https://www.youtube.com/watch?v=IHpR0sP5xXo</a><br>ça ressemble un peu à FAUVE je trouve<br>pas sûr que ça vous plaise, mais j'adhère bien ;)</div></div>",
        'text/plain': "Petit partage à mon tour, pour vous faire découvrir Cabadzi !\r\nhttps://www.youtube.com/watch?v=YnEBdT75RUQ\r\nhttps://www.youtube.com/watch?v=42-Xq5VYrLE\r\nhttps://www.youtube.com/watch?v=IHpR0sP5xXo\r\nça ressemble un peu à FAUVE je trouve\r\npas sûr que ça vous plaise, mais j'adhère bien ;)\r\n\r",
    }
    links = list(extract_links(rawdatum, args=ARGS_NO_PATTERNS))
    assert len(links) == 3


def test_quoted_printable_non_breaking_space(): # =C2=A0
    links = list(extract_links(rawdatum={
        'text/html': email_decode('''<div>Hypnotiq=
ue/m=C3=A9lancolique :=C2=A0<a href=3D"https://www.youtube.com/watch?v=3Do6=
SprGmHTy4">https://www.youtube.com/watch?v=3Do6SprGmHTy4</a></div>''').decode(),
        'text/plain': email_decode('''Hypnotique/m=C3=A9lancolique : https://www.youtube.com/watch?v=3Do6SprGmHTy=
4''').decode(),
    }, args=ARGS_NO_PATTERNS))
    assert len(links) == 1


def test_quote_extraction_with_wiki_style_links():
    # Seen on a Gmail/Outlook exchange
    links = list(extract_links(rawdatum={
        'text/plain': '''Si jamais tu ne connais pas encore, je te propose un peu de Alt-J : \r\n- [ Alt-J - Taro | https://www.youtube.com/watch?v=S3fTw_D3l10 ]''',
        'text/html': '''Si jamais tu ne connais pas encore, je te propose un peu de Alt-J :<br>- <a href="https://www.youtube.com/watch?v=S3fTw_D3l10" target="_blank">Alt-J - Taro</a><br>''',
    }, args=ARGS_NO_PATTERNS))
    links_per_url = {link['url']: link for link in links}
    assert links_per_url['https://www.youtube.com/watch?v=S3fTw_D3l10']['quote'] == 'Si jamais tu ne connais pas encore, je te propose un peu de Alt-J : - <a href="https://www.youtube.com/watch?v=S3fTw_D3l10">Alt-J - Taro</a>'


def test_html_without_a_tag():
    rawdatum = {
        'text/plain': "Voici un petit échantillon de ma playlist:\r\n\r\n\xa0\r\n\r\nTout d'abord de belles reprises selon moi:\r\n\r\nhttps://www.youtube.com/watch?v=lBlbDBaaluY&list=PLpLKHSEzLWPZkyvNVSyBKE_mngyijqH_J&index=2&t=0s \r\n\r",
        'text/html': '<p>Voici un petit échantillon de ma playlist:</p>\r\n<p>\xa0</p>\r\n<p><strong>Tout d\'abord de belles reprises selon moi:</strong></p>\r\n<p>https://www.youtube.com/watch?v=lBlbDBaaluY&list=PLpLKHSEzLWPZkyvNVSyBKE_mngyijqH_J&index=2&t=0s </p>\r\n',
    }
    links = list(extract_links(rawdatum, args=ARGS_NO_PATTERNS))
    links_per_url = {link['url']: link for link in links}
    assert links_per_url['https://www.youtube.com/watch?v=lBlbDBaaluY']['quote'] == '<a href="https://www.youtube.com/watch?v=lBlbDBaaluY">Tout d\'abord de belles reprises selon moi:</a>'


def test_line_breaks_in_quote_and_text():
    rawdatum = {
        "text/plain": "En cherchant des samurais, on trouve ceux des temps modernes\r\n> <https://www.youtube.com/watch?v=BilFJB3H10s>.\r\n>\r\n> ",
        "text/html": "<font face=\"DejaVu Serif\">En c<font face=\"DejaVu Serif\">her<font face=\"DejaVu Serif\">chant des\r\n                                        samurais, on trouve <a href=\"https://www.youtube.com/watch?v=BilFJB3H10s\" target=\"_blank\">ceux\r\n                                          des temps modernes</a>.</font></font></font>",
    }
    links = list(extract_links(rawdatum, args=ARGS_NO_PATTERNS))
    links_per_url = {link['url']: link for link in links}
    assert links_per_url['https://www.youtube.com/watch?v=BilFJB3H10s']['quote'] == 'En cherchant des samurais, on trouve <a href="https://www.youtube.com/watch?v=BilFJB3H10s">ceux des temps modernes</a>.'


def test_line_break_in_url():
    rawdatum = {
        "text/plain": "Un petit morceau folk/blues : https://www.youtube.com/watc\r\n>>> h?v=Q58Gm18-IMY\r\n",
        "text/html": "<div>Un petit morceau folk/blues : <a href=\"https://www.youtube.com/watch?v=Q58Gm18-IMY\" target=\"_blank\">https://www.youtube.com/watc<wbr>h?v=Q58Gm18-IMY</a></div>",
    }
    links = list(extract_links(rawdatum, args=ARGS_NO_PATTERNS))
    assert len(links) == 1
    links_per_url = {link['url']: link for link in links}
    assert links_per_url['https://www.youtube.com/watch?v=Q58Gm18-IMY']['quote'] == '<a href="https://www.youtube.com/watch?v=Q58Gm18-IMY">https://www.youtube.com/watch?v=Q58Gm18-IMY</a>'


def test_wbr_tag_in_url():
    rawdatum = {
        "text/html": "Un groupe 100% Cthulhu : <a href=\"https://www.youtube.com/watch?v=m7qjZuej0Lk\" target=\"_blank\">https://www.youtube.com/watc<wbr>h?v=m7qjZuej0Lk</a>",
        "text/plain": "Un groupe 100% Cthulhu : https://www.youtube.com/watch?v=m7qjZuej0Lk\r\n>>>\r\n",
    }
    links = list(extract_links(rawdatum, args=ARGS_NO_PATTERNS))
    assert len(links) == 1
    links_per_url = {link['url']: link for link in links}
    assert links_per_url['https://www.youtube.com/watch?v=m7qjZuej0Lk']['quote'] == 'Un groupe 100% Cthulhu : <a href="https://www.youtube.com/watch?v=m7qjZuej0Lk">https://www.youtube.com/watch?v=m7qjZuej0Lk</a>'


def test_url_mashups_in_plain_text():
    rawdatum = {
        "text/html": "Cadeaux les québécois sont trop forts, je connais ça<span style=\"font-size: 12pt;\"> depuis un bail, alors je vous l'offre lol. </span><a href=\"https://www.youtube.com/watch?v=mtToc5EmSho\" target=\"_blank\">https://www.youtube.com/watch?v=mtToc5EmSho</a><div>et celle là est pour Kévin <a href=\"https://www.youtube.com/watch?v=AaPZ12bDHh4\">https://www.youtube.com/watch?v=AaPZ12bDHh4</a>",
        "text/plain": "Cadeaux les québécois sont trop forts, je connais ça depuis un bail, alors je vous l'offre lol. https://www.youtube.com/watch?v=mtToc5EmShoet celle là est pour Kévin https://www.youtube.com/watch?v=AaPZ12bDHh4\r\n\r\n\r\n",
    }
    links = list(extract_links(rawdatum, args=ARGS_NO_PATTERNS))
    assert len(links) == 2

    rawdatum = {
        "text/plain": "Juste un podcast de Nova à partager:\r\n> http://www.novaplanet.com/radionova/79043/episode-\r\n> serendipite-musicale-erreurs-heureuses-en-musique-1-la-composition\r\n",
        "text/html": "Juste un podcast de Nova à partager:<br><a href=\"http://www.novaplanet.com/radionova/79043/episode-serendipite-musicale-erreurs-heureuses-en-musique-1-la-composition\" target=\"_blank\">http://www.novaplanet.com/<wbr>radionova/79043/episode-<wbr>serendipite-musicale-erreurs-<wbr>heureuses-en-musique-1-la-<wbr>composition</a>"
    }
    links = list(extract_links(rawdatum, args=ARGS_NO_PATTERNS))
    assert len(links) == 1


def test_extract_quote_no_text():
    plain_text = 'Line above.\nSame line sentence before. Same line same sentence : https://youtu.be/P_XguuxLo10. Same line sentence after.\nLine below.'
    assert extract_quote('https://youtu.be/P_XguuxLo10', plain_text) == 'Same line same sentence :'
    plain_text = 'Line above.\nSame line sentence before. https://youtu.be/P_XguuxLo10. Same line sentence after.\nLine below.'
    assert extract_quote('https://youtu.be/P_XguuxLo10', plain_text) == 'Same line sentence before'
    plain_text = 'Line above.\nhttps://youtu.be/P_XguuxLo10. Same line sentence after.\nLine below.'
    assert extract_quote('https://youtu.be/P_XguuxLo10', plain_text) == 'Line above'


def test_extract_user_email_and_name():
    assert extract_user_email_and_name('bob anderson <bob@anderson.org>') == ('bob@anderson.org', 'bob anderson')
    assert extract_user_email_and_name(r'"\"bob anderson"\" <bob@anderson.org>') == ('bob@anderson.org', 'bob anderson')
    assert extract_user_email_and_name('cc: bob anderson <bob@anderson.org>') == ('bob@anderson.org', 'bob anderson')
    assert extract_user_email_and_name('"bob anderson" (via comfy mailing list)') == ('bob anderson', 'bob anderson')
    assert extract_user_email_and_name('bob@anderson.org') == ('bob@anderson.org', 'bob@anderson.org')
    assert extract_user_email_and_name('<bob@anderson.org>') == ('bob@anderson.org', 'bob@anderson.org')
    assert extract_user_email_and_name('le =?utf-8?q?rest=2c_na=c3=afg?= <bob@anderson.org>') == ('bob@anderson.org', 'le rest, naïg')
    assert extract_user_email_and_name('=?UTF-8?B?S8OpdmluIEJyw6ltb25k?= (via comfy Mailing List) <bob@anderson.org>') == ('bob@anderson.org', 'kévin brémond (via comfy mailing list)')

def test_extract_src_dst():
    rawdatum = {
        'From': 'a@b.com',
        'To': '"ANDERSON, Bob" <bob.anderson@gmail.com>, \r\n\t"ANDERSON, Bobette" <bobette.anderson@gmail.com>'
    }
    expected = {
        'src': {'a@b.com': {'name': 'a@b.com'}},
        'dests': {
            'bob.anderson@gmail.com': {'name': 'anderson, bob'},
            'bobette.anderson@gmail.com': {'name': 'anderson, bobette'},
        }
    }
    assert extract_src_dst(rawdatum) == expected
