import json
import logging
from datetime import datetime

import requests
from flask import current_app
from fhir.resources.auditevent import AuditEvent

from application.oauth_server.service import TokenService, get_timestamp_now

logger = logging.getLogger('fhir_logging_service')
logger.setLevel(logging.DEBUG)


class FhirLoggingService:

    @staticmethod
    def register_idp_interaction(entity_what_reference: str):

        logger.info(f"Registering idp interaction for entity: [{entity_what_reference}]")

        audit_event = FhirLoggingService._get_audit_event(entity_what_reference)
        access_token = token_service.get_system_access_token()

        endpoint = f'{current_app.config["FHIR_CLIENT_SERVERURL"]}/AuditEvent'
        logger.info(f"About to submit AuditEvent to endpoint [{endpoint}]")
        audit_event_json = json.dumps(audit_event)
        logger.info(f"generated audit event json: {audit_event}")
        response = requests.post(endpoint, json=audit_event, headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/fhir+json;charset=utf-8"})

        if response.ok:
            logger.info(f"Audit event created successfully with code [{response.status_code}]")
        else:
            logger.warning(f"Failed to created AuditEvent, server response with code [{response.status_code}] and reason: [{response.reason}]")

        return response

    @staticmethod
    def _get_audit_event(entity_what_reference: str):

        entity_type = entity_what_reference.split("/")[0]
        if entity_type != "Patient" and entity_type != "Practitioner":
            raise Exception(f"Cannot log IDP interaction - Entity type must be Patient or Practitioner. Got [{entity_type}] instead.")

        data = {
            "resourceType": "AuditEvent",
            "meta": {
                "profile":  [
                    "http://koppeltaal.nl/fhir/StructureDefinition/KT2AuditEvent"
                ]
            },
            "type": {
                "system": "http://dicom.nema.org/resources/ontology/DCM",
                "code": "110114",
                "display": "User Authentication"
            },
            "subtype" : {
                "system": "http://dicom.nema.org/resources/ontology/DCM",
                "code": "110122",
                "display": "Login"
            },
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
                        "reference": f"Device/{current_app.config['SMART_BACKEND_SERVICE_DEVICE_ID']}",
                        "type": "Device"
                    },
                    "requestor": True
                }
            ],
            "source": {
                "site": "DEFAULT tenant",
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
                        "code": f"{'1' if entity_type == 'Patient' else '15'}",
                        "display": entity_type
                    }
                }
            ]
        }

        AuditEvent(**data)  # trigger validation
        return data


token_service = TokenService()
fhir_logging_service = FhirLoggingService()
