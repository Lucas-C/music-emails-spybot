from music_emails_spybot import extract_links


def test_extract_links():
    rawdatum = {
        'text/html': '<div><a href="http://https://www.youtube.com/watch?v=Qt-of-5EwhU">http://https://www.youtube.com/watch?v=Qt-of-5EwhU</a><br><br><div>',
        'text/plain': '\r\nhttp://https://www.youtube.com/watch?v=Qt-of-5EwhU\r\n\r\n',
    }

    links = list(extract_links(rawdatum))

    assert links == [{
        'quote': '<a href="https://www.youtube.com/watch?v=Qt-of-5EwhU">http://https://www.youtube.com/watch?v=Qt-of-5EwhU</a>',
        'url': 'https://www.youtube.com/watch?v=Qt-of-5EwhU',
        'text': 'http://https://www.youtube.com/watch?v=Qt-of-5EwhU',
        'tags': set(),
        'email': None
    }]
