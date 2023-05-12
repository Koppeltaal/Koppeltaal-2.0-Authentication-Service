#  Copyright (c) Stichting Koppeltaal 2021.
#
#  This Source Code Form is subject to the terms of the Mozilla Public
#  License, v. 2.0. If a copy of the MPL was not distributed with this
#  file, You can obtain one at https://mozilla.org/MPL/2.0/.
from enum import Enum
from uuid import uuid4

from sqlalchemy import ForeignKey

from application.database import db
from application.oauth_server.guid import GUID

class Oauth2Session(db.Model):
    id = db.Column(GUID(), primary_key=True, default=uuid4, unique=True)

    type = db.Column(db.String(80))  # alter table oauth2_session add column type VARCHAR(80) default 'smart_backend'
    scope = db.Column(db.Text())
    code_challenge = db.Column(db.Text())
    code_challenge_method = db.Column(db.String(128))
    response_type = db.Column(db.String(16))
    client_id = db.Column(db.String(80))
    redirect_uri = db.Column(db.String(128))
    state = db.Column(db.Text())
    launch = db.Column(db.Text())  # alter table oauth2_session modify column launch TEXT
    aud = db.Column(db.String(128))  # alter table oauth2_session add column aud VARCHAR(255)

    user_fhir_reference = db.Column(db.String(80))
    code = db.Column(db.String(80), unique=True, nullable=False)

    def __repr__(self):
        return f'<Oauth2Session {self.id}>'


class Oauth2Token(db.Model):
    id = db.Column(GUID(), primary_key=True, default=uuid4, unique=True)
    client_id = db.Column(db.String(80))
    access_token = db.Column(db.Text())
    refresh_token = db.Column(db.Text())
    id_token = db.Column(db.String(2048))
    scope = db.Column(db.Text())
    subject = db.Column(db.String(128))
    session_id = db.Column(GUID(), db.ForeignKey(Oauth2Session.id))

    def to_json(self):
        return {'client_id': self.client_id,
                'access_token': self.access_token,
                'refresh_token': self.refresh_token,
                'scope': self.scope,
                'subject': self.subject}


class SmartServiceStatus(str, Enum):
    PENDING = 'PENDING'
    APPROVED = 'APPROVED'
    REJECTED = 'REJECTED'


class CrudOperation(Enum):
    CREATE = 'CREATE'
    READ = 'READ'
    UPDATE = 'UPDATE'
    DELETE = 'DELETE'


class PermissionScope(str, Enum):
    ALL = 'ALL'
    OWN = 'OWN'
    GRANTED = 'GRANTED'


class Role(db.Model):
    """
    CREATE TABLE `role` (
      `id` char(36) NOT NULL,
      `created_by` varchar(255) DEFAULT NULL,
      `created_on` datetime DEFAULT NULL,
      `name` varchar(255) DEFAULT NULL,
      PRIMARY KEY (`id`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
    """
    id = db.Column(GUID(), primary_key=True, default=uuid4, unique=True)
    created_by = db.Column(db.String(255))
    created_on = db.Column(db.DateTime())
    name = db.Column(db.String(255))


class SmartService(db.Model):
    """
    CREATE TABLE IF NOT EXISTS public.smart_service
(
    id uuid NOT NULL,
    created_by character varying(255) COLLATE pg_catalog."default",
    created_on timestamp without time zone,
    client_id character varying(255) COLLATE pg_catalog."default",
    fhir_store_device_id character varying(255) COLLATE pg_catalog."default",
    jwks_endpoint character varying(255) COLLATE pg_catalog."default",
    name character varying(255) COLLATE pg_catalog."default",
    public_key character varying(512) COLLATE pg_catalog."default",
    status character varying(255) COLLATE pg_catalog."default",
    role_id uuid,
    patient_idp uuid,
    practitioner_idp uuid,
    CONSTRAINT smart_service_pkey PRIMARY KEY (id),
    CONSTRAINT client_id_index UNIQUE (client_id),
    CONSTRAINT unique_jwks_endpoint UNIQUE (jwks_endpoint),
    CONSTRAINT unique_public_key UNIQUE (public_key),
    CONSTRAINT fkcosi5jmx6d18vmwqhv2h3gmr0 FOREIGN KEY (role_id)
        REFERENCES public.role (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE NO ACTION,
    CONSTRAINT patient_idp_fk FOREIGN KEY (patient_idp)
        REFERENCES public.identity_provider (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE NO ACTION,
    CONSTRAINT practitioner_idp_fk FOREIGN KEY (practitioner_idp)
        REFERENCES public.identity_provider (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE NO ACTION
)
    """
    id = db.Column(GUID(), primary_key=True, default=uuid4, unique=True)
    created_by = db.Column(db.String(255))
    created_on = db.Column(db.DateTime())
    client_id = db.Column(db.String(255))
    jwks_endpoint = db.Column(db.String(255))
    status = db.Column(db.Enum(SmartServiceStatus))
    public_key = db.Column(db.String(512))
    role_id = db.Column(GUID(), ForeignKey(Role.id))
    name = db.Column(db.String(255))
    fhir_store_device_id = db.Column(db.String(255))
    patient_idp = db.Column(GUID(), ForeignKey('identity_provider.id'), nullable=True)
    practitioner_idp = db.Column(GUID(), ForeignKey('identity_provider.id'), nullable=True)


class Permission(db.Model):
    """
    CREATE TABLE `permission` (
      `id` char(36) NOT NULL,
      `created_by` varchar(255) DEFAULT NULL,
      `created_on` datetime DEFAULT NULL,
      `operation` varchar(255) DEFAULT NULL,
      `resource_type` varchar(255) DEFAULT NULL,
      `scope` varchar(255) DEFAULT NULL,
      `role_id` char(36) NOT NULL,
      PRIMARY KEY (`id`),
      UNIQUE KEY `unique_permission` (`role_id`,`resource_type`,`operation`),
      CONSTRAINT `FKrvhjnns4bvlh4m1n97vb7vbar` FOREIGN KEY (`role_id`) REFERENCES `role` (`id`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
    """
    id = db.Column(GUID(), primary_key=True, default=uuid4, unique=True)
    created_by = db.Column(db.String(255))
    created_on = db.Column(db.DateTime())
    operation = db.Column(db.Enum(CrudOperation))
    resource_type = db.Column(db.String(255))
    scope = db.Column(db.Enum(PermissionScope))
    role_id = db.Column(GUID(), ForeignKey("role.id"))
    def __repr__(self):
        return f'{self.resource_type}/{self.scope}.{self.operation}'


class PermissionServiceGrant(db.Model):
    """
    CREATE TABLE `permission_service_grant` (
      `permission_id` char(36) NOT NULL,
      `smart_service_id` char(36) NOT NULL,
      PRIMARY KEY (`permission_id`,`smart_service_id`),
      KEY `FKdc1aains9omcxwoulinqyvr7j` (`smart_service_id`),
      CONSTRAINT `FKcgjhhrn71uynab1031epbovrx` FOREIGN KEY (`permission_id`) REFERENCES `permission` (`id`),
      CONSTRAINT `FKdc1aains9omcxwoulinqyvr7j` FOREIGN KEY (`smart_service_id`) REFERENCES `smart_service` (`id`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
    """
    permission_id = db.Column(GUID(), ForeignKey('permission.id'), primary_key=True)
    smart_service_id = db.Column(GUID(), ForeignKey('smart_service.id'), primary_key=True)

class IdentityProvider(db.Model):
    """
    CREATE TABLE IF NOT EXISTS public.identity_provider
    (
        id uuid NOT NULL,
    created_by character varying(255) COLLATE pg_catalog."default",
    created_on timestamp without time zone,
    client_id character varying(255) COLLATE pg_catalog."default",
    client_secret character varying(255) COLLATE pg_catalog."default",
    endpoint character varying(255) COLLATE pg_catalog."default",
    name character varying(255) COLLATE pg_catalog."default",
    username_attribute character varying(255) COLLATE pg_catalog."default",
    CONSTRAINT identity_provider_pkey PRIMARY KEY (id)
    )
    """
    id = db.Column(GUID(), primary_key=True, default=uuid4, unique=True)
    created_by = db.Column(db.String(255))
    created_on = db.Column(db.DateTime())
    client_id = db.Column(db.String(255))
    client_secret = db.Column(db.String(255))
    endpoint = db.Column(db.String(255))
    name = db.Column(db.String(255))
    username_attribute = db.Column(db.String(255))
