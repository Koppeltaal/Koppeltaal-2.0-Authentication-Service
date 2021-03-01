#  Copyright (c) Stichting Koppeltaal 2021.
#
#  This Source Code Form is subject to the terms of the Mozilla Public
#  License, v. 2.0. If a copy of the MPL was not distributed with this
#  file, You can obtain one at https://mozilla.org/MPL/2.0/.

from time import time
from urllib.parse import urlencode
from uuid import uuid4

from authlib.jose import JsonWebKey, Key
from authlib.jose import jwt
from flask import Blueprint, redirect, request, jsonify, current_app, render_template, session

from application.database import db
from application.irma_client import irma_client
from application.oidc_server.model import Oauth2Session, Oauth2Token


def create_blueprint() -> Blueprint:
    blueprint = Blueprint(__name__.split('.')[-2], __name__)

    @blueprint.route('/oauth2/authorize')
    def authorize():
        oauth_session = Oauth2Session()

        oauth_session.scope = request.values.get('scope')
        oauth_session.response_type = request.values.get('response_type')
        oauth_session.client_id = request.values.get('client_id')
        oauth_session.redirect_uri = request.values.get('redirect_uri')
        oauth_session.state = request.values.get('state')
        oauth_session.code = str(uuid4())

        if 'username' in session:
            username = session['username']
            oauth_session.username = username

        db.session.add(oauth_session)
        db.session.commit()

        # If the username is set, the user is identified.
        if not oauth_session.username is None:
            if not oauth_session.consent:
                return redirect('/oauth2/consent?' + urlencode({'session': oauth_session.id}))
            else:
                return redirect(
                    f'{oauth_session.redirect_uri}?{urlencode({"code": oauth_session.code, "state": oauth_session.state})}')


        return redirect(irma_client.get_redirect_url({'session': oauth_session.id}))

    @blueprint.route('/oauth2/consent', methods=['GET'])
    def consent_get():
        oauth_session_id = request.values['session']
        oauth_session: Oauth2Session = Oauth2Session.query.filter_by(id=oauth_session_id).first()
        scopes = oauth_session.scope.split(' ')
        keep = 'username' in session
        return render_template('oauth2_consent.html', username=oauth_session.username, session=oauth_session_id,
                               scopes=scopes, client_id=oauth_session.client_id,  keep=keep)

    @blueprint.route('/oauth2/consent', methods=['POST'])
    def consent_post():
        oauth_session_id = request.values['session']
        oauth_session: Oauth2Session = Oauth2Session.query.filter_by(id=oauth_session_id).first()

        oauth_session.scope = ' '.join(request.form.getlist('scope'))
        oauth_session.consent = True

        if 'keep' in request.values:
            session['username'] = oauth_session.username
        else:
            session['username'] = None

        db.session.add(oauth_session)
        db.session.commit()

        return redirect(
            f'{oauth_session.redirect_uri}?{urlencode({"code": oauth_session.code, "state": oauth_session.state})}')

    @blueprint.route('/oauth2/token', methods=['POST', 'GET'])
    def token():
        grant_type = request.values.get('grant_type')

        if grant_type == 'authorization_code':
            return token_authorization_code()
        if grant_type == 'refresh_token':
            return token_refresh_token()
        else:
            return 'Bad Request', 400

    def token_refresh_token():
        refresh_token = request.values.get('refresh_token')

        private_key, public_key = get_keypair()
        refresh_token_claims = jwt.decode(refresh_token, public_key)
        if refresh_token_claims.get('exp') < time():
            return 'Bad Request', 400

        scope = request.values.get('scope')
        oauth2_token: Oauth2Token = Oauth2Token.query.filter_by(refresh_token=refresh_token).first()
        if oauth2_token is None:
            return 'Bad Request', 400

        oauth2_session: Oauth2Session = Oauth2Session.query.filter_by(id=oauth2_token.session_id).first()
        if oauth2_session is None:
            return 'Bad Request', 400

        assert scope == oauth2_token.scope
        oauth2_token.id_token = get_id_token(oauth2_token, private_key, public_key)
        oauth2_token.access_token = get_access_token(oauth2_token, oauth2_session, private_key, public_key)
        oauth2_token.refresh_token = get_refresh_token(private_key, public_key)
        db.session.add(oauth2_token)
        db.session.commit()
        return jsonify(oauth2_token_to_json(oauth2_token))

    def oauth2_token_to_json(oauth2_token):
        return {'access_token': oauth2_token.access_token,
                "token_type": "Bearer",
                "refresh_token": oauth2_token.refresh_token,
                "id_token": oauth2_token.id_token,
                "expires_in": current_app.config['OIDC_JWT_EXP_TIME_ACCESS_TOKEN']}

    def token_authorization_code():
        code = request.values.get('code')
        redirect_uri = request.values.get('redirect_uri')
        ## TODO: The token request must be autheticated.
        oauth2_session: Oauth2Session = Oauth2Session.query.filter_by(code=code).first()
        assert redirect_uri == oauth2_session.redirect_uri
        oauth2_token = Oauth2Token()
        oauth2_token.subject = oauth2_session.username
        oauth2_token.scope = oauth2_session.scope
        oauth2_token.client_id = oauth2_session.client_id
        private_key, public_key = get_keypair()
        oauth2_token.id_token = get_id_token(oauth2_token, private_key, public_key)
        oauth2_token.access_token = get_access_token(oauth2_token, oauth2_session, private_key, public_key)
        oauth2_token.refresh_token = get_refresh_token(private_key, public_key)
        oauth2_token.session_id = oauth2_session.id
        db.session.add(oauth2_token)
        db.session.commit()
        return jsonify(oauth2_token_to_json(oauth2_token))

    def get_keypair():
        public_key: Key = JsonWebKey.import_key(current_app.config['OIDC_JWT_PUBLIC_KEY'])
        private_key: Key = JsonWebKey.import_key(current_app.config['OIDC_JWT_PRIVATE_KEY'])
        return private_key, public_key

    def get_id_token(oauth2_token: Oauth2Token, private_key: Key, public_key: Key) -> str:
        return _get_jwt_token(current_app.config['OIDC_JWT_EXP_TIME_ACCESS_TOKEN'], private_key,
                              public_key, oauth2_token.client_id, sub=oauth2_token.subject, email=oauth2_token.subject)

    def get_access_token(oauth2_token: Oauth2Token, oauth_session: Oauth2Session, private_key: Key,
                         public_key: Key) -> str:
        return _get_jwt_token(current_app.config['OIDC_JWT_EXP_TIME_ACCESS_TOKEN'], private_key,
                              public_key, 'fhir-server', type='access', sub=oauth2_token.subject,
                              scope=oauth_session.scope)

    def get_refresh_token(private_key: Key, public_key: Key) -> str:
        return _get_jwt_token(current_app.config['OIDC_JWT_EXP_TIME_REFRESH_TOKEN'], private_key,
                              public_key, 'fhir-server', type='refresh')

    def _get_jwt_token(expiry: int, private_key: Key, public_key: Key, aud: str, type: str = None, sub: str = None,
                       email: str = None, scope: str = None) -> str:
        payload = {
            'iss': request.url_root,
            'aud': aud,
            'nbf': time(),
            'exp': time() + expiry,
            'nonce': str(uuid4())}
        if type is not None:
            payload['type'] = type

        if sub is not None:
            payload['sub'] = sub

        if email is not None:
            payload['email'] = email

        if scope is not None:
            payload['scope'] = scope

        header = {'kid': public_key.thumbprint(), 'alg': 'RS512'}
        return jwt.encode(header, payload, private_key).decode('ascii')

    @blueprint.route('/oauth2/irma-auth')
    def irma_auth():
        token = request.values['token']
        oauth_session_id = request.values['session']
        username = irma_client.validate_token(token)

        oauth_session: Oauth2Session = Oauth2Session.query.filter_by(id=oauth_session_id).first()
        oauth_session.username = username

        db.session.commit()

        if not oauth_session.consent:
            return redirect('/oauth2/consent?' + urlencode({'session': oauth_session.id}))
        else:
            return redirect(
                f'{oauth_session.redirect_uri}?{urlencode({"code": oauth_session.code, "state": oauth_session.state})}')

    return blueprint
