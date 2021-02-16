#  Copyright (c) Stichting Koppeltaal 2021.
#
#  This Source Code Form is subject to the terms of the Mozilla Public
#  License, v. 2.0. If a copy of the MPL was not distributed with this
#  file, You can obtain one at https://mozilla.org/MPL/2.0/.

from urllib.parse import urlparse, urlencode

import requests
from authlib.jose import JsonWebKey, jwt
from flask import request, current_app, redirect


class IrmaClient:
    def __init__(self):
        pass

    def _get_url_base(self):
        o = urlparse(request.base_url)
        if o.port is None or o.port == -1:
            server_base = f'{o.scheme}://{o.hostname}'
        else:
            server_base = f'{o.scheme}://{o.hostname}:{o.port}'
        return server_base

    def get_redirect_url(self, params):
        server_base = self._get_url_base()
        redirect_uri = f'{server_base}/oauth2/irma-auth?{urlencode(params)}'
        irma_url = f'{current_app.config["IRMA_CLIENT_SERVER_URL"]}?{urlencode({"redirect_uri": redirect_uri})}'
        return irma_url

    def validate_token(self, token):
        jwks_url = f'{current_app.config["IRMA_CLIENT_SERVER_URL"]}/.well-known/jwks.json'
        with requests.get(jwks_url) as resp:
            keyset = JsonWebKey.import_key_set(resp.json())

        decode = jwt.decode(token, keyset)
        return decode.get('sub')

irma_client = IrmaClient()
