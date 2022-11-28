from collections import defaultdict
from typing import List

from application.oauth_server.model import Permission, CrudOperation, PermissionServiceGrant


class ScopeService():
    @staticmethod
    def get_crud_str(operations: List[CrudOperation]):
        rv = ''
        if CrudOperation.CREATE in operations:
            rv += 'c'
        if CrudOperation.READ in operations:
            rv += 'r'
        if CrudOperation.UPDATE in operations:
            rv += 'u'
        if CrudOperation.DELETE in operations:
            rv += 'd'
        return rv

    def get_scopes(self, role_id, own_device_id):
        permissions = Permission.query.filter_by(role_id=role_id).all()
        crud_map = defaultdict(list)
        for permission in permissions:
            scope = permission.scope
            if scope == 'ALL':
                scope = '*'
            elif scope == 'OWN':
                scope = own_device_id
            elif scope == 'GRANTED':
                scope = self.get_granted(permission.id)
            operation: CrudOperation = permission.operation
            crud_key = f"{scope}/{permission.resource_type}"
            crud_map[crud_key].append(operation)

        rv = []
        for key, value in crud_map.items():
            action = self.get_crud_str(value)
            rv.append(f"{key}.{action}")

        return rv

    def get_scope_str(self, role_id, own_device_id):
        return ' '.join(self.get_scopes(role_id, own_device_id))

    def get_granted(self, permission_id):
        rv: List[str] = []
        permissions_grants: List[PermissionServiceGrant] = PermissionServiceGrant.query.filter_by(
            permission_id=permission_id).all()
        for permissions_grant in permissions_grants:
            rv.append(permissions_grant.smart_service_id)
        return rv


scope_service = ScopeService()
