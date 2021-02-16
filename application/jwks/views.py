#  Copyright (c) Stichting Koppeltaal 2021.
#
#  This Source Code Form is subject to the terms of the Mozilla Public
#  License, v. 2.0. If a copy of the MPL was not distributed with this
#  file, You can obtain one at https://mozilla.org/MPL/2.0/.

from authlib.jose import JsonWebKey, KeySet, Key
from flask import Blueprint, current_app, jsonify


def create_blueprint() -> Blueprint:
    blueprint = Blueprint(__name__.split('.')[-2], __name__)

    @blueprint.route('/.well-known/jwks.json')
    def jwks():
        key: Key = JsonWebKey.import_key(current_app.config['OIDC_JWT_PUBLIC_KEY'])
        key_set: KeySet = KeySet([key])

        return jsonify(key_set.as_dict())

    return blueprint
