#  Copyright (c) Stichting Koppeltaal 2021.
#
#  This Source Code Form is subject to the terms of the Mozilla Public
#  License, v. 2.0. If a copy of the MPL was not distributed with this
#  file, You can obtain one at https://mozilla.org/MPL/2.0/.

from authlib.jose import JsonWebKey, Key
from flask import Flask
from flask_behind_proxy import FlaskBehindProxy
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy

from application import oauth_server, jwks, idp_client
from application.database import db
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
    setup_database(app)
    ensure_oidc_keys(app)
    cors = CORS(app, resources={r"/oauth2/*": {"origins": "*"}}, supports_credentials=True)
    db = SQLAlchemy(app)
    return app


def setup_database(app: Flask):
    """
    Creates
    :param app: the Flask application instance.
    """
    db.init_app(app)
    with app.app_context():
        db.create_all()
