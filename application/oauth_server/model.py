#  Copyright (c) Stichting Koppeltaal 2021.
#
#  This Source Code Form is subject to the terms of the Mozilla Public
#  License, v. 2.0. If a copy of the MPL was not distributed with this
#  file, You can obtain one at https://mozilla.org/MPL/2.0/.

from uuid import uuid4

from application.database import db
from application.oauth_server.guid import GUID


class Oauth2Session(db.Model):
    id = db.Column(GUID(), primary_key=True, default=uuid4, unique=True)

    scope = db.Column(db.String(80))
    response_type = db.Column(db.String(16))
    client_id = db.Column(db.String(80))
    redirect_uri = db.Column(db.String(128))
    state = db.Column(db.String(128))
    launch = db.Column(db.String(512))

    username = db.Column(db.String(80))
    email = db.Column(db.String(80))
    name_given = db.Column(db.String(80))
    name_family = db.Column(db.String(80))
    user_fhir_reference = db.Column(db.String(80))
    code = db.Column(db.String(80), unique=True, nullable=False)
    consent = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f'<Oauth2Session {self.id}>'


class Oauth2ClientCredentials(db.Model):
    id = db.Column(GUID(), primary_key=True, default=uuid4, unique=True)
    client_id = db.Column(db.String(80))
    client_secret = db.Column(db.String(80))

class Oauth2Token(db.Model):
    id = db.Column(GUID(), primary_key=True, default=uuid4, unique=True)
    client_id = db.Column(db.String(80))
    access_token = db.Column(db.String(256))
    refresh_token = db.Column(db.String(256))
    id_token = db.Column(db.String(256))
    scope = db.Column(db.String(128))
    subject = db.Column(db.String(128))
    email = db.Column(db.String(128))
    name_given = db.Column(db.String(128))
    name_family = db.Column(db.String(128))
    session_id = db.Column(GUID(), db.ForeignKey(Oauth2Session.id))

    def to_json(self):
        return {'client_id': self.client_id,
                'access_token': self.access_token,
                'refresh_token': self.refresh_token,
                'scope': self.scope,
                'subject': self.subject}
