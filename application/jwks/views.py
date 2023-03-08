#  Copyright (c) Stichting Koppeltaal 2021.
#
#  This Source Code Form is subject to the terms of the Mozilla Public
#  License, v. 2.0. If a copy of the MPL was not distributed with this
#  file, You can obtain one at https://mozilla.org/MPL/2.0/.

from authlib.jose import KeySet, Key
from flask import Blueprint, current_app, jsonify, abort

from application.jwks.service import keypair_service
from application.utils import oidc_smart_config_cached


def create_blueprint() -> Blueprint:
    blueprint = Blueprint(__name__.split('.')[-2], __name__)

    @blueprint.route('/.well-known/jwks.json')
    @oidc_smart_config_cached()
    def jwks():
        key: Key = keypair_service.get_public_key()
        key_set: KeySet = KeySet([key])

        return jsonify(key_set.as_dict())

    @blueprint.route('/.well-known/smart-configuration', methods=['GET'])
    @oidc_smart_config_cached()
    def smart_configuration():
        if (not current_app.config['OIDC_SMART_CONFIG_ENABLED']):
            abort(404)

        return jsonify(
            token_endpoint=(current_app.config['OIDC_SMART_CONFIG_TOKEN_ENDPOINT']),
            token_endpoint_auth_methods_supported=(current_app.config['OIDC_SMART_CONFIG_AUTH_METHODS']),
            token_endpoint_auth_signing_alg_values_supported=(current_app.config['OIDC_SMART_CONFIG_SIGNING_ALGS']),
            scopes_supported=(current_app.config['OIDC_SMART_CONFIG_SCOPES']),
            registration_endpoint=(current_app.config['OIDC_SMART_CONFIG_REGISTRATION_ENDPOINT']))

    return blueprint
