#  Copyright (c) Stichting Koppeltaal 2021.
#
#  This Source Code Form is subject to the terms of the Mozilla Public
#  License, v. 2.0. If a copy of the MPL was not distributed with this
#  file, You can obtain one at https://mozilla.org/MPL/2.0/.
from enum import Enum
from uuid import uuid4

from application.database import db
from application.oauth_server.guid import GUID


class Oauth2Session(db.Model):
    id = db.Column(GUID(), primary_key=True, default=uuid4, unique=True)

    type = db.Column(db.String(80)) # alter table oauth2_session add column type VARCHAR(80) default 'smart_backend'
    scope = db.Column(db.String(80))
    code_challenge = db.Column(db.String(2048))
    code_challenge_method = db.Column(db.String(128))
    response_type = db.Column(db.String(16))
    client_id = db.Column(db.String(80))
    redirect_uri = db.Column(db.String(128))
    state = db.Column(db.String(128))
    launch = db.Column(db.Text()) # alter table oauth2_session modify column launch TEXT
    aud = db.Column(db.String(128)) # alter table oauth2_session add column aud VARCHAR(255)

    user_fhir_reference = db.Column(db.String(80))
    code = db.Column(db.String(80), unique=True, nullable=False)

    def __repr__(self):
        return f'<Oauth2Session {self.id}>'


class Oauth2Token(db.Model):
    id = db.Column(GUID(), primary_key=True, default=uuid4, unique=True)
    client_id = db.Column(db.String(80))
    access_token = db.Column(db.String(2048))
    refresh_token = db.Column(db.String(2048))
    id_token = db.Column(db.String(2048))
    scope = db.Column(db.String(128))
    subject = db.Column(db.String(128))
    session_id = db.Column(GUID(), db.ForeignKey(Oauth2Session.id))

    def to_json(self):
        return {'client_id': self.client_id,
                'access_token': self.access_token,
                'refresh_token': self.refresh_token,
                'scope': self.scope,
                'subject': self.subject}


class SmartService(db.Model):
    id = db.Column(GUID(), primary_key=True, default=uuid4, unique=True)
    created_by = db.Column(db.String(255))
    client_id = db.Column(db.String(255))
    jwks_endpoint = db.Column(db.String(255))
    status = db.Column(db.String(255))
    public_key = db.Column(db.String(255))


class SmartServiceStatus(str, Enum):
    PENDING = 'PENDING'
    APPROVED = 'APPROVED'
    REJECTED = 'REJECTED'
