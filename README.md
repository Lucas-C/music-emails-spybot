[![build status](https://github.com/Lucas-C/music-emails-spybot/workflows/build/badge.svg)](https://github.com/Lucas-C/music-emails-spybot/actions?query=branch%3Amaster)
[![Known Vulnerabilities](https://snyk.io/test/github/lucas-c/music-emails-spybot/badge.svg)](https://snyk.io/test/github/lucas-c/music-emails-spybot)

# Music emails Spybot

![](https://chezsoi.org/lucas/ComfySpy.jpg)

You have been exchanging emails with links to music videos for years with some friends ?
This script will generates an HTML page summarizing all those exchanges, as an archive to this precious playlist.

Also: despite its name, this tool is in no way limited to music. It will happily scrape any hyperlinks in your emails.


## Demo

[ComfySpy](https://chezsoi.org/lucas/ComfySpy.html)


## Installation

    pip3 install -r requirements.txt


## Usage
First, you will need to create a OAuth user access to a Google Cloud app with `readonly` access to the GMail API.
This will give you a `client_secret.json` file.
Then you can:

    ./get_gmail_api_token.py  # produces token.json - require a browser
    ./music_emails_spybot.py ComfySpy --email-subject Comfy


## Contributing
Bug reports or features suggestions are warmly welcome !

For the devs:

    pip3 install pre-commit pytest
    pre-commit install

Executing a single test:

    py.test -k test_fct


## Ideas for new features

- make links extraction smarter by ignoring bottom of emails containing previous messages
_cf._ https://github.com/Lucas-C/music-emails-spybot/issues/1 - Current workaround is to only read first 5000 chars
- split `main` into tasks, that save their state into the JSON memory file when they finish, so that it'd be possible to exec only 1 task (fetch emails / extract quotes / generate HTML...)
- for each task, show its duration & memory usage
- publish on Pypi
- handle multiple input subjects / the full Gmail search syntax
- auto-generate a Youtube playlist
- i18n
