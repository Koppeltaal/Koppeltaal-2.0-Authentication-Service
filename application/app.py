#  Copyright (c) Stichting Koppeltaal 2021.
#
#  This Source Code Form is subject to the terms of the Mozilla Public
#  License, v. 2.0. If a copy of the MPL was not distributed with this
#  file, You can obtain one at https://mozilla.org/MPL/2.0/.

from authlib.jose import JsonWebKey, Key
from cryptography.hazmat.primitives import serialization
from flask import Flask
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy

from application import oidc_server, jwks
from application.database import db


def register_blueprints(app):
    app.register_blueprint(oidc_server.views.create_blueprint())
    app.register_blueprint(jwks.views.create_blueprint())


def register_error_handlers(app):
    pass


def ensure_oidc_keys(app):
    if not app.config['OIDC_JWT_PUBLIC_KEY'] or not app.config['OIDC_JWT_PRIVATE_KEY']:
        print('OIDC_JWT_PUBLIC_KEY or OIDC_JWT_PRIVATE_KEY is not set, generating a pair')
        key: Key = JsonWebKey.generate_key('RSA', 2048, is_private=True)
        key.check_key_op('sign')
        public_key = key.get_public_key()
        private_key = key.get_private_key()
        public_key_bytes = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                   format=serialization.PublicFormat.SubjectPublicKeyInfo)
        app.config['OIDC_JWT_PUBLIC_KEY'] = public_key_bytes
        private_key_bytes = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                      format=serialization.PrivateFormat.PKCS8,
                                                      encryption_algorithm=serialization.NoEncryption())
        app.config['OIDC_JWT_PRIVATE_KEY'] = private_key_bytes

    pass


def create_app(config=None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    if config is None:
        # load the instance config, if it exists, when not testing
        app.config.from_pyfile('config.py')
    else:
        # load the test config if passed in
        app.config.from_mapping(config)

    # if 'APP_SECRET_KEY' in app.config:
    #     app.secret_key = app.config['APP_SECRET_KEY']
    register_blueprints(app)
    register_error_handlers(app)
    setup_database(app)
    ensure_oidc_keys(app)
    cors = CORS(app, resources={r"/auth/*": {"origins": "*"}}, supports_credentials=True)
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
