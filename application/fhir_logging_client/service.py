import logging
from datetime import datetime

import requests
from flask import current_app
from fhir.resources.auditevent import AuditEvent

from application.oauth_server.service import TokenService
from application.utils import new_trace_headers

logger = logging.getLogger('fhir_logging_service')
logger.setLevel(logging.DEBUG)


class FhirLoggingService:

    @staticmethod
    def register_idp_interaction(entity_what_reference: str, requesting_client_id: str, trace_headers: dict):

        logger.info(f"Registering idp interaction for entity: [{entity_what_reference}]")

        audit_event = FhirLoggingService._get_audit_event(entity_what_reference, requesting_client_id, trace_headers)
        access_token = token_service.get_system_access_token()

        endpoint = f'{current_app.config["FHIR_CLIENT_SERVERURL"]}/AuditEvent'
        logger.info(f"About to submit AuditEvent to endpoint [{endpoint}]")
        logger.info(f"generated audit event json: {audit_event}")
        headers = new_trace_headers(trace_headers,
                                    {"Authorization": f"Bearer {access_token}",
                                     "Content-Type": "application/fhir+json;charset=utf-8"})
        response = requests.post(endpoint, json=audit_event, headers=headers)

        if response.ok:
            logger.info(f"Audit event created successfully with code [{response.status_code}]")
        else:
            logger.warning(f"Failed to created AuditEvent, server response with code [{response.status_code}] and reason: [{response.reason}]")

        return response

    @staticmethod
    def _get_audit_event(entity_what_reference: str, requesting_client_id: str, trace_headers: dict):

        entity_type = entity_what_reference.split("/")[0]
        if entity_type != "Patient" and entity_type != "Practitioner" and entity_type != "RelatedPerson":
            raise Exception(f"Cannot log IDP interaction - Entity type must be Patient, Practitioner or RelatedPerson. Got [{entity_type}] instead.")

        extension_ = []
        if 'X-Request-Id' in trace_headers:
            extension_.append({
                "url": "http://koppeltaal.nl/fhir/StructureDefinition/request-id",
                "valueId": trace_headers['X-Request-Id']
            })
        if 'X-Correlation-Id' in trace_headers:
            extension_.append({
                "url": "http://koppeltaal.nl/fhir/StructureDefinition/correlation-id",
                "valueId": trace_headers['X-Correlation-Id']
            })
        if 'X-Trace-Id' in trace_headers:
            extension_.append({
                "url": "http://koppeltaal.nl/fhir/StructureDefinition/trace-id",
                "valueId": trace_headers['X-Trace-Id']
            })
        data = {
            "resourceType": "AuditEvent",
            "meta": {
                "profile":  [
                    "http://koppeltaal.nl/fhir/StructureDefinition/KT2AuditEvent"
                ]
            },
            "extension": extension_,
            "type": {
                "system": "http://dicom.nema.org/resources/ontology/DCM",
                "code": "110114",
                "display": "User Authentication"
            },
            "subtype" : [{
                "system": "http://dicom.nema.org/resources/ontology/DCM",
                "code": "110122",
                "display": "Login"
            }],
            "action": "E",
            "outcome": "0",
            "recorded": datetime.utcnow().isoformat("T", "milliseconds") + "+00:00",
            "agent":  [
                {
                    "type": {
                        "coding":  [
                            {
                                "system": "http://dicom.nema.org/resources/ontology/DCM",
                                "code": "110153"
                            }
                        ]
                    },
                    "who": {
                        "reference": f"Device/{requesting_client_id}",
                        "type": "Device"
                    },
                    "requestor": True
                }
            ],
            "source": {
                "site": current_app.config['AUTH_SERVER_ISS'],
                "observer": {
                    "reference": f"Device/{current_app.config['SMART_BACKEND_SERVICE_DEVICE_ID']}",
                    "type": "Device"
                }
            },
            "entity":  [
                {
                    "what": {
                        "reference": entity_what_reference,
                        "type": entity_type
                    },
                    "role": {
                        "system": "http://terminology.hl7.org/CodeSystem/object-role",
                        "code": f"{'1' if entity_type == 'Patient' else '6' if entity_type == 'RelatedPerson' else '15'}",
                        "display":f"{'User' if entity_type == 'RelatedPerson' else entity_type }",
                    }
                }
            ]
        }

        AuditEvent(**data)  # trigger validation
        return data


token_service = TokenService()
fhir_logging_service = FhirLoggingService()
