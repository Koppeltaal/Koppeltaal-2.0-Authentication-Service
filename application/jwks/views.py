#  Copyright (c) Stichting Koppeltaal 2021.
#
#  This Source Code Form is subject to the terms of the Mozilla Public
#  License, v. 2.0. If a copy of the MPL was not distributed with this
#  file, You can obtain one at https://mozilla.org/MPL/2.0/.

from authlib.jose import KeySet, Key
from flask import Blueprint, current_app, jsonify, abort, request

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
            issuer=request.url_root,
            jwks_uri=f'{request.host_url}.well-known/jwks.json',
            authorization_endpoint=f'{request.host_url}oauth2/authorize',
            grant_types_supported=['authorization_code', 'client_credentials'],
            token_endpoint=f'{request.host_url}oauth2/token',
            token_endpoint_auth_methods_supported=['private_key_jwt'],
            scopes_supported=["openid", "launch", "fhirUser", "system/*.cruds", "system/*.cruds?resource-origin="],
            response_types_supported=['code'],
            management_endpoint=current_app.config['OIDC_SMART_CONFIG_MANAGEMENT_ENDPOINT'],
            introspection_endpoint=f'{request.host_url}oauth2/introspect',
            capabilities=['launch-ehr', 'authorize-post', 'client-confidential-asymmetric', 'sso-openid-connect',
                          'context-ehr-hti', 'permission-v2'],
            code_challenge_methods_supported=['S256'])

    return blueprint
