#!/usr/bin/env python3

# This script require a client_secret.json file to exists,
# and will produce a token.json file as output.
# Inspired by: https://github.com/UtkarshVerma/i3blocklets
# This could also be done using Google Python libraries, like in: https://github.com/Lucas-C/youtube_playlist_watcher/blob/master/playlistItems_delete.py

import json, requests
from socketserver import StreamRequestHandler, TCPServer
from urllib.parse import parse_qs

SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
SECRET_JSON_FILE = "client_secret.json"
PORT = 7331
OAUTH_CODE = None

class OauthCodeRequestHandler(StreamRequestHandler):
    """
    Retrieve the OAuth 'code' query param from GMail callback request,
    and store it in OAUTH_CODE global variable.
    """
    def handle(self):
        # pylint: disable=global-statement
        global OAUTH_CODE
        tcp_request = self.rfile.readline(65537).decode('utf8')
        _, uri, _ = tcp_request.split(' ', maxsplit=2)
        query = parse_qs(uri[2:])
        OAUTH_CODE = query["code"][0]
        self.wfile.write("OK!\nNow back to your shell".encode('utf8'))
        self.wfile.flush()

with open(SECRET_JSON_FILE, encoding="utf-8") as secret_file:
    client_secret = json.load(secret_file)["installed"]

redirect_uri = f"http://localhost:{PORT}"
print(f'Please visit this URL in a browser: https://accounts.google.com/o/oauth2/v2/auth?client_id={client_secret["client_id"]}&redirect_uri={redirect_uri}&response_type=code&scope={SCOPE}&access_type=offline')

with TCPServer(("localhost", PORT), OauthCodeRequestHandler) as server:
    server.handle_request()

resp = requests.post("https://www.googleapis.com/oauth2/v4/token", json={
    "code": OAUTH_CODE,
    "client_id": client_secret["client_id"],
    "client_secret": client_secret["client_secret"],
    "grant_type": "authorization_code",
    "redirect_uri": redirect_uri,
})
resp.raise_for_status()
print('OAuth token successfully retrieved')

with open("token.json", "w", encoding="utf-8") as token_file:
    json.dump(resp.json(), token_file)
print('token.json generated')
