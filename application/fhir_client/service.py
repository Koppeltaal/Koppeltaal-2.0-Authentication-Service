import json
import urllib.request
import urllib.request
from urllib.parse import quote
from urllib.request import Request

from flask import current_app

from application.oidc_server.service import token_service


class FhirClient:
    def __init__(self):
        pass

    def get_fhir_person(self, username, access_token):
        bundle = self.get_resource_by_identifier('IRMA', username, access_token, 'Person')
        return self.read_bundle(bundle)

    def read_bundle(self, bundle):
        if bundle['resourceType'] == 'Bundle':
            total = bundle['total']
            if total > 0:
                return bundle['entry'][0]['resource']

        return None

    def create_fhir_person(self, username, access_token):
        user = {
            'resourceType': 'Person',
            'identifier': [
                {
                    'system': 'IRMA',
                    'value': username
                }
            ]}
        rv = self.create_resource(access_token, user)
        return rv

    def get_fhir_patient(self, username, access_token):
        bundle = self.get_resource_by_identifier('IRMA', username, access_token, 'Patient')
        return self.read_bundle(bundle)

    def get_fhir_practitioner(self, username, access_token):
        bundle = self.get_resource_by_identifier('IRMA', username, access_token, 'Practitioner')
        return self.read_bundle(bundle)

    def get_fhir_related_person(self, username, access_token):
        bundle = self.get_resource_by_identifier('IRMA', username, access_token, 'RelatedPerson')
        return self.read_bundle(bundle)

    def _get_server_base(self):
        return current_app.config['FHIR_CLIENT_SERVERURL']

    def get_resource_by_identifier(self, identifier_system, identifier_value, access_token, resource_type):
        server_base = self._get_server_base()
        identifier = f'{identifier_system}|{identifier_value}'
        search_url = f'{server_base}/{resource_type}/_search?identifier={quote(identifier)}&_format=json'
        request = Request(search_url)
        request.add_header(f'Authorization', f'Bearer {access_token}')
        with urllib.request.urlopen(request) as response:
            return json.loads(response.read())

    def create_resource(self, access_token, resource):
        server_base = self._get_server_base()
        resource_url = f'{server_base}/{resource["resourceType"]}'
        request = Request(resource_url, data=json.dumps(resource).encode('utf-8'))
        request.add_header('Content-Type', 'application/json')
        request.add_header(f'Authorization', f'Bearer {access_token}')
        with urllib.request.urlopen(request) as response:
            return json.loads(response.read())

    def get_or_create_fhir_user(self, username) -> dict:
        token = token_service.get_system_access_token(username)

        fhir_user = fhir_client.get_fhir_patient(username, token)
        if not fhir_user:
            fhir_user = fhir_client.get_fhir_practitioner(username, token)
        if not fhir_user:
            fhir_user = fhir_client.get_fhir_related_person(username, token)
        if not fhir_user:
            fhir_user = fhir_client.get_fhir_person(username, token)

        if not fhir_user:
            fhir_user = fhir_client.create_fhir_person(username, token)

        return fhir_user


fhir_client = FhirClient()
