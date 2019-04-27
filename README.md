[![](https://travis-ci.org/Lucas-C/music-emails-spybot.svg?branch=master)](https://travis-ci.org/Lucas-C/music-emails-spybot)
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

If you're using Gmail, all you really need is to generate an [app password for this script to access your emails](https://security.google.com/settings/security/apppasswords),
and to give it a string that appears in all the subjects of the emails you want to parse :

    read -s IMAP_PASSWORD
    ./music_emails_spybot.py ComfySpy --email-subject Comfy --imap-username lucascimon --imap-password $IMAP_PASSWORD


## Installation en tâche cronnée

    cat <<EOF > /etc/cron.d/music_emails_spybot_crontask
    00 00 * * * $USER (date && "$PWD/music_emails_spybot.py" ComfySpy --email-subject Comfy --imap-username lucascimon --imap-password $IMAP_PASSWORD >> "$PWD/ComfySpy.log" 2>&1)
    EOF


## Contributing

[![Requirements Status](https://requires.io/github/Lucas-C/music-emails-spybot/requirements.svg?branch=master)](https://requires.io/github/Lucas-C/music-emails-spybot/requirements/?branch=master)

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
