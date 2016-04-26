# Music emails Spybot

![](https://chezsoi.org/lucas/ComfySpy.jpg)


## Demo

[ComfySpy](https://chezsoi.org/lucas/ComfySpy.html)


## Installation

    pip3 install --user Jinja1 requests


## Usage

    read -s IMAP_PASSWORD
    ./music_emails_spybot.py ComfySpy --email-subject Comfy --imap-username lucascimon --imap-password $IMAP_PASSWORD --ignored-links-pattern 'novaplanet\.com|urbandictionary\.com|xkcd\.com|\.gif$|\.jpe?g$'


## Contributing

[![Requirements Status](https://requires.io/github/Lucas-C/music-emails-spybot/requirements.svg?branch=master)](https://requires.io/github/Lucas-C/music-emails-spybot/requirements/?branch=master)

Bug reports or features suggestions are warmly welcome !

For the devs:

    pip3 install --user pre-commit
    pre-commit install

