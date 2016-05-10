from music_emails_spybot import extract_links


def test_tags_extraction():
    rawdatum = {
        'text/html': '<div dir="ltr">Merci :)<br>Bwarf, j\'ai pas trop envie de paginer franchement.<br><br>Allez zou, un petit morceau de #pop qui rend #happy : <a href="https://www.youtube.com/watch?v=uJ_1HMAGb4k">https://www.youtube.com/watch?v=uJ_1HMAGb4k</a></div>',
        'text/plain': 'Merci :)\r\nBwarf, j\'ai pas trop envie de paginer franchement.\r\n\r\nAllez zou, un petit morceau de #pop qui rend #happy :\r\nhttps://www.youtube.com/watch?v=uJ_1HMAGb4k\r\n\r\n',
    }

    links = list(extract_links(rawdatum, ignored_links_pattern=None, email_msg=None))

    assert links[0]['quote'] == 'Allez zou, un petit morceau de <a href="#pop">#pop</a> qui rend <a href="#happy">#happy</a> : <a href="https://www.youtube.com/watch?v=uJ_1HMAGb4k">https://www.youtube.com/watch?v=uJ_1HMAGb4k</a>'


def test_multiple_links_with_same_quote():
    rawdatum = {
        'text/html': 'Je ne vais pas trop m’étendre étant donné que je n\'est bien exploré que leur dernier album pour le moment (<a href="https://i.ytimg.com/vi/4-FTRHflHFs/maxresdefault.jpg">Cooking with pagans</a>), mais c\'est du <a href="https://www.youtube.com/watch?v=y9ytbURTs40">Hard Rock</a>, <a href="https://www.youtube.com/watch?v=tRx8AAht9jY">Heavy Metal</a>, <a href="https://www.youtube.com/watch?v=30bQJuKbN3E">Progressive Metal</a> bien barré (mention spéciale pour "<a href="https://www.youtube.com/watch?v=qoSpzbE31KA">Anal bleach</a>" et toute la poésie qui se dégage du titre).',
        'text/plain': 'Je ne vais pas trop m’étendre étant donné que je n\'est bien exploré que\r\nleur dernier album pour le moment (Cooking with pagans\r\n<https://i.ytimg.com/vi/4-FTRHflHFs/maxresdefault.jpg>), mais c\'est du Hard\r\nRock <https://www.youtube.com/watch?v=y9ytbURTs40>, Heavy Metal\r\n<https://www.youtube.com/watch?v=tRx8AAht9jY>, Progressive Metal\r\n<https://www.youtube.com/watch?v=30bQJuKbN3E> bien barré (mention spéciale\r\npour "Anal bleach <https://www.youtube.com/watch?v=qoSpzbE31KA>" et toute\r\nla poésie qui se dégage du titre).',
    }

    links = list(extract_links(rawdatum, ignored_links_pattern=None, email_msg=None))

    assert len(links) == 5  # 4 Youtube links + 1 jpg
    assert all(link['quote'].count('<a href=') == 1 for link in links)


def test_workaround_typo():
    rawdatum = {
        'text/html': '<div><a href="http://https://www.youtube.com/watch?v=Qt-of-5EwhU">http://https://www.youtube.com/watch?v=Qt-of-5EwhU</a><br><br><div>',
        'text/plain': '\r\nhttp://https://www.youtube.com/watch?v=Qt-of-5EwhU\r\n\r\n',
    }

    links = list(extract_links(rawdatum, ignored_links_pattern=None, email_msg=None))

    assert links[0]['quote'] == '<a href="https://www.youtube.com/watch?v=Qt-of-5EwhU">http://https://www.youtube.com/watch?v=Qt-of-5EwhU</a>'

