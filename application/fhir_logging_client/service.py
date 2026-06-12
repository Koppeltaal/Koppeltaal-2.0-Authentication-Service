import logging
from datetime import datetime, timezone

import requests
from fhir.resources.auditevent import AuditEvent
from flask import current_app

from application.oauth_server.service import TokenService
from application.utils import new_trace_headers

logger = logging.getLogger('fhir_logging_service')
logger.setLevel(logging.DEBUG)

DCM_SYSTEM = "http://dicom.nema.org/resources/ontology/DCM"

PERSON_ROLE_CODES = {
    "Patient": {"code": "1", "display": "Patient"},
    "RelatedPerson": {"code": "6", "display": "User"},
    "Practitioner": {"code": "15", "display": "Practitioner"},
}


class FhirLoggingService:

    @staticmethod
    def register_login(entity_what_reference: str, requesting_client_id: str, trace_headers: dict):
        return FhirLoggingService._register_user_authentication_event(
            "110122", "Login",
            requesting_client_id, trace_headers,
            entity_what_reference=entity_what_reference)

    @staticmethod
    def register_idp_delegation(entity_what_reference: str, requesting_client_id: str,
                                idp_name: str, idp_issuer: str, trace_headers: dict):
        return FhirLoggingService._register_user_authentication_event(
            "110144", "Authentication Delegated to IdP",
            requesting_client_id, trace_headers,
            entity_what_reference=entity_what_reference,
            idp_name=idp_name, idp_issuer=idp_issuer)

    @staticmethod
    def register_idp_decision(entity_what_reference: str, requesting_client_id: str,
                              idp_name: str, idp_issuer: str, outcome: str, trace_headers: dict):
        return FhirLoggingService._register_user_authentication_event(
            "110145", "IdP Authentication Decision",
            requesting_client_id, trace_headers,
            outcome=outcome,
            entity_what_reference=entity_what_reference,
            idp_name=idp_name, idp_issuer=idp_issuer)

    @staticmethod
    def register_token_introspection(agent_who_reference: str, requesting_client_id: str,
                                     trace_headers: dict):
        return FhirLoggingService._register_user_authentication_event(
            "110143", "Token Introspection (HTI launch)",
            requesting_client_id, trace_headers,
            agent_who_reference=agent_who_reference)

    @staticmethod
    def _register_user_authentication_event(subtype_code: str, subtype_display: str,
                                            requesting_client_id: str, trace_headers: dict,
                                            outcome: str = "0",
                                            entity_what_reference: str = None,
                                            idp_name: str = None, idp_issuer: str = None,
                                            agent_who_reference: str = None):
        logger.info(f"Registering User Authentication AuditEvent (subtype [{subtype_code}]) "
                    f"for client [{requesting_client_id}]")
        try:
            data = FhirLoggingService._base_user_authentication_event(
                subtype_code, subtype_display, requesting_client_id, outcome, trace_headers)
            if entity_what_reference is not None:
                FhirLoggingService._add_person_entity(data, entity_what_reference)
            if idp_name or idp_issuer:
                FhirLoggingService._add_idp_agent(data, idp_name, idp_issuer)
            if agent_who_reference is not None:
                FhirLoggingService._add_person_agent(data, agent_who_reference)
            AuditEvent(**data)  # trigger validation
        except Exception:
            logger.exception(f"Failed to build User Authentication AuditEvent (subtype [{subtype_code}])")
            return None
        return FhirLoggingService._post_audit_event(data, trace_headers)

    @staticmethod
    def _base_user_authentication_event(subtype_code: str, subtype_display: str,
                                        requesting_client_id: str, outcome: str,
                                        trace_headers: dict) -> dict:
        return {
            "resourceType": "AuditEvent",
            "meta": {
                "profile": [
                    "http://koppeltaal.nl/fhir/StructureDefinition/KT2AuditEvent"
                ]
            },
            "extension": FhirLoggingService._trace_extensions(trace_headers),
            "type": {
                "system": DCM_SYSTEM,
                "code": "110114",
                "display": "User Authentication"
            },
            "subtype": [{
                "system": DCM_SYSTEM,
                "code": subtype_code,
                "display": subtype_display
            }],
            "action": "E",
            "outcome": outcome,
            "recorded": datetime.now(timezone.utc).isoformat("T", "milliseconds"),
            "agent": [
                {
                    "type": {
                        "coding": [
                            {
                                "system": DCM_SYSTEM,
                                "code": "110153",
                                "display": "Source Role ID"
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
                },
                "type": [{
                    "system": "http://terminology.hl7.org/CodeSystem/security-source-type",
                    "code": "6",
                    "display": "Security Server"
                }]
            }
        }

    @staticmethod
    def _trace_extensions(trace_headers: dict) -> list:
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
        return extension_

    @staticmethod
    def _person_type(reference: str) -> str:
        person_type = (reference or "").split("/")[0]
        if person_type not in PERSON_ROLE_CODES:
            raise ValueError(f"Entity type must be Patient, Practitioner or RelatedPerson. "
                             f"Got [{person_type}] instead.")
        return person_type

    @staticmethod
    def _add_person_entity(data: dict, entity_what_reference: str):
        person_type = FhirLoggingService._person_type(entity_what_reference)
        role = PERSON_ROLE_CODES[person_type]
        data["entity"] = [
            {
                "what": {
                    "reference": entity_what_reference,
                    "type": person_type
                },
                "role": {
                    "system": "http://terminology.hl7.org/CodeSystem/object-role",
                    "code": role["code"],
                    "display": role["display"]
                }
            }
        ]

    @staticmethod
    def _add_idp_agent(data: dict, idp_name: str, idp_issuer: str):
        agent_who = {}
        if idp_name:
            agent_who["display"] = idp_name
        if idp_issuer:
            agent_who["identifier"] = {
                "system": "http://koppeltaal.nl/oidc/issuer",
                "value": idp_issuer
            }
        data["agent"].append({
            "type": {
                "coding": [
                    {
                        "system": DCM_SYSTEM,
                        "code": "110152",
                        "display": "Destination Role ID"
                    }
                ]
            },
            "who": agent_who,
            "requestor": False
        })

    @staticmethod
    def _add_person_agent(data: dict, reference: str):
        person_type = FhirLoggingService._person_type(reference)
        data["agent"].append({
            "who": {
                "reference": reference,
                "type": person_type
            },
            "requestor": False
        })

    @staticmethod
    def _post_audit_event(data: dict, trace_headers: dict):
        try:
            access_token = token_service.get_system_access_token()
            endpoint = f'{current_app.config["FHIR_CLIENT_SERVERURL"]}/AuditEvent'
            logger.info(f"About to submit AuditEvent to endpoint [{endpoint}]")
            logger.info(f"generated audit event json: {data}")
            headers = new_trace_headers(trace_headers,
                                        {"Authorization": f"Bearer {access_token}",
                                         "Content-Type": "application/fhir+json;charset=utf-8"})
            response = requests.post(endpoint, json=data, headers=headers)
        except Exception:
            logger.exception("Failed to submit AuditEvent to the FHIR server")
            return None

        if response.ok:
            logger.info(f"Audit event created successfully with code [{response.status_code}]")
        else:
            logger.warning(f"Failed to create AuditEvent, server responded with code "
                           f"[{response.status_code}] and reason: [{response.reason}]")
        return response

    @staticmethod
    def register_idp_interaction(entity_what_reference: str,
                                 requesting_client_id: str,
                                 idp_name: str,
                                 idp_issuer: str,
                                 trace_headers: dict):

        logger.info(f"Registering idp interaction for entity: [{entity_what_reference}]")

        audit_event = FhirLoggingService._get_audit_event(entity_what_reference, requesting_client_id,
                                                          idp_name, idp_issuer,
                                                          trace_headers)
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
    def _get_audit_event(entity_what_reference: str,
                         requesting_client_id: str,
                         idp_name: str,
                         idp_issuer: str,
                         trace_headers: dict):

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
            "recorded": datetime.now(timezone.utc).isoformat("T", "milliseconds"),
            "agent":  [
                {
                    "type": {
                        "coding":  [
                            {
                                "system": "http://dicom.nema.org/resources/ontology/DCM",
                                "code": "110153",
                                "display": "Source Role ID"
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
                },
                "type" : [{
                  "system": "http://terminology.hl7.org/CodeSystem/security-source-type",
                  "code": "6",
                  "display": "Security Server"
                }]
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

        if idp_name or idp_issuer:
            agent_who ={}
            if idp_name:
                agent_who["display"] = idp_name
            if idp_issuer:
                agent_who["identifier"] = {
                    "system": "http://koppeltaal.nl/oidc/issuer",
                    "value": idp_issuer
                }
            data["agent"].append({
                "type": {
                    "coding": [
                        {
                            "system": "http://dicom.nema.org/resources/ontology/DCM",
                            "code": "110152",
                            "display": "Destination Role ID"
                        }
                    ]
                },
                "who": agent_who,
                "requestor": False
            })

        AuditEvent(**data)  # trigger validation
        return data


token_service = TokenService()
fhir_logging_service = FhirLoggingService()
