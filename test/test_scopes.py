from datetime import datetime
from uuid import uuid4

import pytest
from authlib.jose import JsonWebKey, Key

from application import create_app
from application.database import db
from application.oauth_server.model import SmartService, SmartServiceStatus, PermissionServiceGrant, Role, Permission, \
    CrudOperation, PermissionScope
from application.oauth_server.scopes import scope_service
from application.utils import get_private_key_as_pem


@pytest.fixture()
def server_key() -> Key:
    key: Key = JsonWebKey.generate_key('RSA', 2048, is_private=True)
    key.check_key_op('sign')
    yield key


@pytest.fixture()
def testing_app(server_key: Key):
    private_key_bytes = get_private_key_as_pem(server_key)
    app = create_app({'TESTING': True,
                      'SQLALCHEMY_TRACK_MODIFICATIONS': False,
                      'SQLALCHEMY_DATABASE_URI': "sqlite:////tmp/test.db",
                      'OIDC_SMART_CONFIG_TOKEN_ENDPOINT': 'http://localhost:8080/endpoint',
                      'OIDC_JWT_EXP_TIME_ACCESS_TOKEN': 60,
                      'FHIR_CLIENT_SERVERURL': 'http://fhir-server.com/url',
                      'IDP_AUTHORIZE_CLIENT_ID': str(uuid4()),
                      'IDP_AUTHORIZE_REDIRECT_URL': 'http://localhost:5000/idp/oidc/code',
                      'IDP_AUTHORIZE_ENDPOINT': 'http://localhost:5000/idp/authorize',
                      'IDP_TOKEN_ENDPOINT': 'http://localhost:5000/idp/token',
                      'IDP_AUTHORIZE_CLIENT_SECRET': str(uuid4()),
                      'SMART_BACKEND_SERVICE_CLIENT_ID': str(uuid4()),
                      'OIDC_SMART_CONFIG_SIGNING_ALGS': ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"],
                      'OIDC_JWT_PUBLIC_KEY': server_key.as_pem(),
                      'OIDC_JWT_PRIVATE_KEY': private_key_bytes})
    with app.test_client() as client:
        with app.app_context():
            yield client


@pytest.fixture()
def smart_service(client_id, smart_service_role: Role, own_device_id):
    smart_service = SmartService(created_by='admin',
                                 client_id=client_id,
                                 status=SmartServiceStatus.APPROVED,
                                 role_id=smart_service_role.id,
                                 fhir_store_device_id=own_device_id)
    db.session.add(smart_service)
    db.session.commit()
    yield smart_service


@pytest.fixture()
def smart_service_other():
    smart_service = SmartService(created_by='admin',
                                 client_id=str(uuid4()),
                                 status=SmartServiceStatus.APPROVED)
    db.session.add(smart_service)
    db.session.commit()
    yield smart_service


@pytest.fixture()
def smart_service_role(testing_app):
    role = Role(name='role1', created_by='admin', created_on=datetime.now())
    db.session.add(role)
    db.session.commit()
    return role


@pytest.fixture()
def permissions(smart_service_role: Role):
    perms = []
    perms += permission_create([CrudOperation.READ],
                               'Patient',
                               smart_service_role.id,
                               PermissionScope.ALL)
    perms += permission_create([CrudOperation.READ],
                               'RelatedPerson',
                               smart_service_role.id,
                               PermissionScope.ALL)
    perms += permission_create([CrudOperation.READ],
                               'RelatedPerson',
                               smart_service_role.id,
                               PermissionScope.OWN)
    perms += permission_create([CrudOperation.CREATE, CrudOperation.UPDATE],
                               'RelatedPerson',
                               smart_service_role.id,
                               PermissionScope.OWN)
    perms += permission_create([CrudOperation.CREATE, CrudOperation.UPDATE],
                               'Task',
                               smart_service_role.id,
                               PermissionScope.OWN)
    perms += permission_create([CrudOperation.READ],
                               'Task',
                               smart_service_role.id,
                               PermissionScope.GRANTED)
    perms += permission_create([CrudOperation.READ],
                               'Task',
                               smart_service_role.id,
                               PermissionScope.OWN)
    db.session.commit()

    yield perms


@pytest.fixture()
def grants(permissions, smart_service_other):
    grants = []
    for permission in permissions:
        if permission.scope == PermissionScope.GRANTED:
            grant = PermissionServiceGrant(permission_id=permission.id, smart_service_id=smart_service_other.id)
            db.session.add(grant)
            grants.append(grant)
    db.session.commit()
    yield grants


def permission_create(operations, resource_type, role_id, scope):
    rv = []
    for operation in operations:
        permission = Permission(operation=operation, resource_type=resource_type, role_id=role_id, scope=scope)
        db.session.add(permission)
        rv.append(permission)
    return rv


@pytest.fixture()
def own_device_id() -> str:
    return str(uuid4())


def test_happy(testing_app, smart_service_role: Role, own_device_id, permissions, grants,
               smart_service_other: SmartService):
    scopes = scope_service.get_scopes(smart_service_role.id, own_device_id)
    assert 'system/Patient.rs' in scopes
    assert 'system/RelatedPerson.rs' in scopes
    assert f'system/RelatedPerson.crus?resource-origin=Device/{own_device_id}' in scopes
    assert f'system/Task.crus?resource-origin=Device/{own_device_id}' in scopes
    assert f'system/Task.rs?resource-origin=Device/{smart_service_other.fhir_store_device_id}' in scopes


def test_unk(testing_app):
    scopes = scope_service.get_scopes(str(uuid4()), 'ABCD')
    assert len(scopes) == 0
