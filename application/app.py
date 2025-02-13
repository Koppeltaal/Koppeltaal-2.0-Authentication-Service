#  Copyright (c) Stichting Koppeltaal 2021.
#
#  This Source Code Form is subject to the terms of the Mozilla Public
#  License, v. 2.0. If a copy of the MPL was not distributed with this
#  file, You can obtain one at https://mozilla.org/MPL/2.0/.
import logging
from urllib import response

import requests
from authlib.jose import JsonWebKey, Key
from flask import Flask
from flask_behind_proxy import FlaskBehindProxy
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy

from application import oauth_server, jwks, idp_client
from application.database import db
from .fhir_logging_client.service import token_service
from .utils import get_private_key_as_pem, get_public_key_as_pem


def register_blueprints(app):
    app.register_blueprint(oauth_server.views.create_blueprint())
    app.register_blueprint(jwks.views.create_blueprint())
    app.register_blueprint(idp_client.views.create_blueprint())


def register_error_handlers(app):
    pass


def ensure_oidc_keys(app):
    if not _has_config_key_set(app, 'OIDC_JWT_PUBLIC_KEY') or not _has_config_key_set(app, 'OIDC_JWT_PRIVATE_KEY'):
        print('OIDC_JWT_PUBLIC_KEY or OIDC_JWT_PRIVATE_KEY is not set, generating a pair')
        key: Key = JsonWebKey.generate_key('RSA', 2048, is_private=True)
        key.check_key_op('sign')
        public_key_bytes = get_public_key_as_pem(key)
        app.config['OIDC_JWT_PUBLIC_KEY'] = public_key_bytes
        private_key_bytes = get_private_key_as_pem(key)
        app.config['OIDC_JWT_PRIVATE_KEY'] = private_key_bytes



def _has_config_key_set(app, cnfg_key_name):
    return cnfg_key_name in app.config and len(app.config[cnfg_key_name]) > 0


def ensure_device(app):
    access_token = token_service.get_system_access_token()

    headers = {"Authorization": "Bearer " + access_token}
    ## First test if the device can be found with the own credentials
    device_response = requests.get(
        f'{app.config["FHIR_CLIENT_SERVERURL"]}/Device/{app.config["SMART_BACKEND_SERVICE_CLIENT_ID"]}',
        headers=headers)
    if not device_response.status_code == 404:
        ## If the device cannot be located, attempt to create one WITHOUT a security context, assuming the
        ## FHIR server security is disabled to bootstrap the domain.
        logging.log(logging.WARN, "Attempting to create the device without security context")
        device_response = requests.put(f'{app.config["FHIR_CLIENT_SERVERURL"]}/Device/{app.config["SMART_BACKEND_SERVICE_CLIENT_ID"]}', json={
            "resourceType": "Device",
            "id": app.config["SMART_BACKEND_SERVICE_CLIENT_ID"],
            "meta": {
                "profile": [
                    "http://koppeltaal.nl/fhir/StructureDefinition/KT2Device"
                ]
            },
            "identifier": [
                {
                    "system": "http://vzvz.nl/fhir/NamingSystem/koppeltaal-client-id",
                    "value": app.config["SMART_BACKEND_SERVICE_CLIENT_ID"],
                }
            ],
            "status": "active",
            "deviceName": [
                {
                    "name": "Auth Service",
                    "type": "user-friendly-name"
                }
            ]
        })
        if not device_response.ok:
            raise "Failed to create device with id " + app.config["SMART_BACKEND_SERVICE_CLIENT_ID"] + " in FHIR server. Please disable the security in the FHIR server and try again."
        else:
            logging.log(logging.WARN, "Succeeded to create the device without security context")
    elif not device_response.ok:
        raise "Failed to find device with id " + app.config["SMART_BACKEND_SERVICE_CLIENT_ID"] + " in FHIR server. Status code is: " + str(device_response.status_code) + "."



def create_app(config=None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    FlaskBehindProxy(app)
    if config is None:
        # load the instance config, if it exists, when not testing
        app.config.from_pyfile('config.py')
    else:
        # load the test config if passed in
        app.config.from_mapping(config)

    register_blueprints(app)
    register_error_handlers(app)
    db = setup_database(app)
    ensure_oidc_keys(app)
    with app.app_context():
        if not 'TESTING' in app.config:
            ensure_device(app)
    cors = CORS(app, resources={r"/oauth2/*": {"origins": "*"}}, supports_credentials=True)
    return app


def setup_database(app: Flask):
    """
    Creates
    :param app: the Flask application instance.
    """
    db.init_app(app)
    with app.app_context():
        db.create_all()
    return db
