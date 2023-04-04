from collections import defaultdict
from typing import List

from application.oauth_server.model import Permission, CrudOperation, PermissionServiceGrant, PermissionScope, \
    SmartService


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
        if CrudOperation.READ in operations:
            rv += 's'
        return rv

    def get_scopes(self, role_id, own_device_id):
        permissions = Permission.query.filter_by(role_id=role_id).all()
        crud_map = defaultdict(list)
        for permission in permissions:
            operation: CrudOperation = permission.operation
            permission_scope: PermissionScope = permission.scope
            resource_type = permission.resource_type
            if permission_scope in {PermissionScope.ALL, PermissionScope.OWN}:
                crud_map[f'{resource_type}🐍{permission_scope.value}'].append(operation)
            else:
                crud_map[f'{resource_type}🐍{permission_scope.value}🐍{permission.id}'].append(operation)

        rv = []
        for key, operations in crud_map.items():
            fragments = key.split('🐍')
            resource_type, scope = fragments[0], fragments[1]
            if scope == 'ALL':
                scope = ''
            elif scope == 'OWN':
                scope = f'Device/{own_device_id}'
            elif scope == 'GRANTED':
                permission_id = fragments[2]
                scope = self.get_granted(permission_id)
                if len(scope) == 0:
                    # No scope found, just stop here for this item
                    continue

            action = self.get_crud_str(operations)

            permission_line = f"system/{resource_type}"
            if len(action) > 0:
                permission_line += f'.{action}'
            if len(scope) > 0:
                permission_line += f'?resource-origin={scope}'
            rv.append(permission_line)

        return rv

    def get_scope_str(self, role_id, own_device_id):
        return ' '.join(self.get_scopes(role_id, own_device_id))

    def get_granted(self, permission_id):
        rv: List[str] = []
        permissions_grants: List[PermissionServiceGrant] = PermissionServiceGrant.query.filter_by(
            permission_id=permission_id).all()
        for permissions_grant in permissions_grants:
            smart_service = SmartService.query.filter_by(id=permissions_grant.smart_service_id).first()
            rv.append(f'Device/{smart_service.fhir_store_device_id}')

        return ",".join([str(x) for x in rv])


scope_service = ScopeService()
