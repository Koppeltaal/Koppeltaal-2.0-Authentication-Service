#  Copyright (c) Stichting Koppeltaal 2021.
#
#  This Source Code Form is subject to the terms of the Mozilla Public
#  License, v. 2.0. If a copy of the MPL was not distributed with this
#  file, You can obtain one at https://mozilla.org/MPL/2.0/.

import os
import uuid


def envget_str(key: str, dflt: str = '') -> str:
    """
    Gets a value from the os.environ, and defaults to the value of dflt if not set in the environment.
    :param key: environment variable name
    :param dflt: default value, if not present in the environment
    :return: either the value of the environment variable or the default value (dflt)
    """
    return os.environ[key] if key in os.environ else dflt


def envget_int(key: str, dflt: int = 0) -> int:
    """
    Gets a value from the os.environ, and defaults to the value of dflt if not set in the environment.
    :param key: environment variable name
    :param dflt: default value, if not present in the environment
    :return: either the value of the environment variable or the default value (dflt)
    """
    return int(os.environ[key]) if key in os.environ else dflt


def envget_bool(key, dflt: bool = False) -> bool:
    """
    Gets a value from the os.environ, and defaults to the value of dflt if not set in the environment.
    :param key: environment variable name
    :param dflt: default value, if not present in the environment
    :return: either the value of the environment variable or the default value (dflt)
    """
    val = envget_str(key, 'True' if dflt else 'False')
    return val.lower() in ['true', 'yes', '1', 'y']

def envget_list(key: str, dflt: list = '') -> list:
    """
    Gets a value from the os.environ, and defaults to the value of dflt if not set in the environment.
    :param key: environment variable name
    :param dflt: default value, if not present in the environment
    :return: either the value of the environment variable or the default value (dflt)
    """
    return list(os.environ[key]) if key in os.environ else dflt


DEBUG = envget_bool('DEBUG', False)

SECRET_KEY = envget_str('APP_SECRET_KEY', str(uuid.uuid1()))
SESSION_TYPE = envget_str('APP_SESSION_TYPE', 'filesystem')
IRMA_CLIENT_SERVER_URL = envget_str('IRMA_CLIENT_SERVER_URL', "https://irma-auth.sns.gidsopenstandaarden.org/")

FHIR_CLIENT_SERVERURL = envget_str('FHIR_CLIENT_SERVERURL', "http://localhost:8080/fhir")

SQLALCHEMY_DATABASE_URI = envget_str('SQLALCHEMY_DATABASE_URI', "sqlite:////tmp/koppeltaal-irma-idp.db")
SQLALCHEMY_TRACK_MODIFICATIONS = envget_bool('SQLALCHEMY_TRACK_MODIFICATIONS', False)
OIDC_JWT_PUBLIC_KEY = envget_str('OIDC_JWT_PUBLIC_KEY', '')
OIDC_JWT_PRIVATE_KEY = envget_str('OIDC_JWT_PRIVATE_KEY', '')
OIDC_JWT_EXP_TIME_ACCESS_TOKEN = envget_int('OIDC_JWT_EXP_TIME_ACCESS_TOKEN', 60)

# IdP is used to retrieve the id_token of the logged-in user
IDP_AUTHORIZE_ENDPOINT = envget_str('IDP_AUTHORIZE_ENDPOINT', 'https://iam.koppeltaal.headease.nl/auth/realms/Koppeltaal2/protocol/openid-connect/auth')
IDP_TOKEN_ENDPOINT = envget_str('IDP_TOKEN_ENDPOINT', 'https://iam.koppeltaal.headease.nl/auth/realms/Koppeltaal2/protocol/openid-connect/token')
IDP_AUTHORIZE_CLIENT_ID = envget_str('IDP_AUTHORIZE_CLIENT_ID', 'poc-auth-service')
IDP_AUTHORIZE_CLIENT_SECRET = envget_str('IDP_AUTHORIZE_CLIENT_SECRET', '<SECRET>')
IDP_AUTHORIZE_REDIRECT_URL = envget_str('IDP_AUTHORIZE_REDIRECT_URL', '/idp/oidc/code')

SMART_BACKEND_SERVICE_CLIENT_ID = envget_str('SMART_BACKEND_SERVICE_CLIENT_ID', 'd44ba2e2-4762-465f-b825-d2b291d07db6')

# https://hl7.org/fhir/uv/bulkdata/authorization/index.html#advertising-server-conformance-with-smart-backend-services
OIDC_SMART_CONFIG_ENABLED = envget_bool('OIDC_SMART_CONFIG_ENABLED', False)
OIDC_SMART_CONFIG_TOKEN_ENDPOINT = envget_str('OIDC_SMART_CONFIG_TOKEN_ENDPOINT', FHIR_CLIENT_SERVERURL + '/oauth2/token')
OIDC_SMART_CONFIG_REGISTRATION_ENDPOINT = envget_str('OIDC_SMART_CONFIG_REGISTRATION_ENDPOINT', 'https://smart-backend-services.koppeltaal.headease.nl/register')
OIDC_SMART_CONFIG_AUTH_METHODS = envget_list('OIDC_SMART_CONFIG_AUTH_METHODS', ["private_key_jwt"])
OIDC_SMART_CONFIG_SIGNING_ALGS = envget_list('OIDC_SMART_CONFIG_SIGNING_ALGS', ["RS384", "ES384", "RS512"])
OIDC_SMART_CONFIG_SCOPES = envget_str('OIDC_SMART_CONFIG_SCOPES', '')

