"""
Unit tests for IDP selection logic in OAuth authorization flow.

Acceptance Criteria:
2. De auth server moet:
   a. de custom claim idp_hint uit de launch token herkennen
   b. als deze niet gezet is:
      i. Indien er geen custom IdP geconfigureerd is voor het gebruikerstype, moet de default KT2 IdP gebruikt worden
      ii. De eerste custom IdP die geconfigureerd is voor het gebruikerstype moet gebruikt worden
   c. Als deze wel gezet is moet de waarde van de idp_hint gebruikt worden om te kijken of deze IdP geconfigureerd is
      in domeinbeheer voor het type gebruiker die de launch uitvoert.
      i. Zo ja: gebruik deze IdP
      ii. Zo nee:
         1. Indien er geen custom IdP geconfigureerd is voor het gebruikerstype, moet de default KT2 IdP gebruikt worden
         2. De eerste custom IdP die geconfigureerd is voor het gebruikerstype moet gebruikt worden
"""

import pytest
from uuid import uuid4
from unittest.mock import Mock
from application.oauth_server.views import select_identity_provider


class TestIdpSelection:
    """Test IDP selection logic using actual select_identity_provider function"""

    @pytest.fixture
    def smart_service_no_custom_idps(self):
        """SmartService with no custom IDPs configured"""
        service = Mock()
        service.client_id = 'test-client-123'
        service.patient_idps = []
        service.practitioner_idps = []
        service.related_person_idps = []
        return service

    @pytest.fixture
    def smart_service_with_patient_idps(self):
        """SmartService with multiple Patient IDPs configured in order"""
        service = Mock()
        service.client_id = 'test-client-456'

        # Patient IDPs (ordered by idp_order)
        idp1 = Mock()
        idp1.id = str(uuid4())
        idp1.logical_identifier = 'patient-idp-1'
        idp1.name = 'Patient IDP 1'
        idp1.client_id = 'patient-idp-1-client'
        idp1.openid_config_endpoint = 'http://patient-idp-1/.well-known/openid-configuration'

        idp2 = Mock()
        idp2.id = str(uuid4())
        idp2.logical_identifier = 'patient-idp-2'
        idp2.name = 'Patient IDP 2'
        idp2.client_id = 'patient-idp-2-client'
        idp2.openid_config_endpoint = 'http://patient-idp-2/.well-known/openid-configuration'

        service.patient_idps = [idp1, idp2]  # idp1 is first (default)
        service.practitioner_idps = []
        service.related_person_idps = []
        return service

    @pytest.fixture
    def smart_service_with_all_idps(self):
        """SmartService with IDPs configured for all actor types"""
        service = Mock()
        service.client_id = 'test-client-789'

        # Patient IDPs
        patient_idp = Mock()
        patient_idp.id = str(uuid4())
        patient_idp.logical_identifier = 'patient-idp-default'
        patient_idp.name = 'Patient IDP Default'
        patient_idp.client_id = 'patient-idp-client'
        patient_idp.openid_config_endpoint = 'http://patient-idp/.well-known/openid-configuration'

        # Practitioner IDPs
        prac_idp1 = Mock()
        prac_idp1.id = str(uuid4())
        prac_idp1.logical_identifier = 'practitioner-idp-1'
        prac_idp1.name = 'Practitioner IDP 1'
        prac_idp1.client_id = 'prac-idp-1-client'
        prac_idp1.openid_config_endpoint = 'http://prac-idp-1/.well-known/openid-configuration'

        prac_idp2 = Mock()
        prac_idp2.id = str(uuid4())
        prac_idp2.logical_identifier = 'practitioner-idp-2'
        prac_idp2.name = 'Practitioner IDP 2'
        prac_idp2.client_id = 'prac-idp-2-client'
        prac_idp2.openid_config_endpoint = 'http://prac-idp-2/.well-known/openid-configuration'

        # RelatedPerson IDPs
        related_idp = Mock()
        related_idp.id = str(uuid4())
        related_idp.logical_identifier = 'related-person-idp-default'
        related_idp.name = 'RelatedPerson IDP Default'
        related_idp.client_id = 'related-idp-client'
        related_idp.openid_config_endpoint = 'http://related-idp/.well-known/openid-configuration'

        service.patient_idps = [patient_idp]
        service.practitioner_idps = [prac_idp1, prac_idp2]
        service.related_person_idps = [related_idp]
        return service

    def create_launch_token(self, sub, idp_hint=None):
        """Helper to create launch token payload"""
        token = {
            'sub': sub,
            'aud': 'http://fhir-server',
            'iss': 'test-issuer'
        }
        if idp_hint:
            token['idp_hint'] = idp_hint
        return token

    # Test 2.b.i: No idp_hint, no custom IDP -> use default KT2 IDP
    def test_no_idp_hint_no_custom_idp_patient(self, smart_service_no_custom_idps):
        """When no idp_hint and no custom IDP, should return None (default KT2 IDP)"""
        launch_token = self.create_launch_token('Patient/123')
        selected_idp = select_identity_provider(smart_service_no_custom_idps, launch_token)

        # Should return None indicating default KT2 IDP should be used
        assert selected_idp is None

    # Test 2.b.ii: No idp_hint, has custom IDP -> use first custom IDP
    def test_no_idp_hint_has_custom_idp_patient(self, smart_service_with_patient_idps):
        """When no idp_hint but custom IDPs exist, should return first IDP"""
        launch_token = self.create_launch_token('Patient/456')
        selected_idp = select_identity_provider(smart_service_with_patient_idps, launch_token)

        # Should return first IDP
        assert selected_idp is not None
        assert selected_idp.name == 'Patient IDP 1'
        assert selected_idp == smart_service_with_patient_idps.patient_idps[0]

    # Test 2.c.i: Valid idp_hint matching configured IDP -> use that IDP
    def test_valid_idp_hint_matching_configured_idp(self, smart_service_with_patient_idps):
        """When valid idp_hint matches configured IDP, should return that IDP"""
        # Use second IDP's logical_identifier as hint
        second_idp = smart_service_with_patient_idps.patient_idps[1]
        launch_token = self.create_launch_token('Patient/789', idp_hint=second_idp.logical_identifier)
        selected_idp = select_identity_provider(smart_service_with_patient_idps, launch_token)

        # Should return second IDP (matching the hint)
        assert selected_idp is not None
        assert selected_idp.name == 'Patient IDP 2'
        assert selected_idp.logical_identifier == second_idp.logical_identifier

    # Test 2.c.ii.1: Invalid idp_hint, no custom IDP -> use default KT2 IDP
    def test_invalid_idp_hint_no_custom_idp(self, smart_service_no_custom_idps):
        """When invalid idp_hint and no custom IDP, should return None (default KT2 IDP)"""
        launch_token = self.create_launch_token('Patient/111', idp_hint='invalid-idp-id')
        selected_idp = select_identity_provider(smart_service_no_custom_idps, launch_token)

        # Should return None indicating default KT2 IDP should be used
        assert selected_idp is None

    # Test 2.c.ii.2: Invalid idp_hint, has custom IDP -> use first custom IDP
    def test_invalid_idp_hint_has_custom_idp(self, smart_service_with_patient_idps):
        """When invalid idp_hint but custom IDPs exist, should return first IDP"""
        launch_token = self.create_launch_token('Patient/222', idp_hint='non-existent-idp-id')
        selected_idp = select_identity_provider(smart_service_with_patient_idps, launch_token)

        # Should return first IDP (fallback)
        assert selected_idp is not None
        assert selected_idp.name == 'Patient IDP 1'

    # Test with Practitioner actor type
    def test_practitioner_no_idp_hint_has_custom_idp(self, smart_service_with_all_idps):
        """Practitioner: no idp_hint but custom IDPs exist"""
        launch_token = self.create_launch_token('Practitioner/333')
        selected_idp = select_identity_provider(smart_service_with_all_idps, launch_token)

        # Should return first Practitioner IDP
        assert selected_idp is not None
        assert selected_idp.name == 'Practitioner IDP 1'

    # Test with RelatedPerson actor type
    def test_relatedperson_valid_idp_hint(self, smart_service_with_all_idps):
        """RelatedPerson: valid idp_hint matching configured IDP"""
        related_idp = smart_service_with_all_idps.related_person_idps[0]
        launch_token = self.create_launch_token('RelatedPerson/444', idp_hint=related_idp.logical_identifier)
        selected_idp = select_identity_provider(smart_service_with_all_idps, launch_token)

        # Should return the hinted RelatedPerson IDP
        assert selected_idp is not None
        assert selected_idp.name == 'RelatedPerson IDP Default'
        assert selected_idp.logical_identifier == related_idp.logical_identifier

    # Test IDP ordering is preserved
    def test_idp_ordering_preserved(self, smart_service_with_patient_idps):
        """Verify IDPs are used in the configured order (first = default)"""
        # First IDP should be index 0
        first_idp = smart_service_with_patient_idps.patient_idps[0]
        second_idp = smart_service_with_patient_idps.patient_idps[1]

        assert first_idp.name == 'Patient IDP 1'
        assert second_idp.name == 'Patient IDP 2'

        # When no hint, first IDP should be selected
        launch_token = self.create_launch_token('Patient/555')
        selected_idp = select_identity_provider(smart_service_with_patient_idps, launch_token)

        assert selected_idp == first_idp

    # Test missing 'sub' field raises ValueError
    def test_missing_sub_field_raises_error(self, smart_service_with_patient_idps):
        """When launch token is missing 'sub' field, should raise ValueError"""
        launch_token = {'aud': 'http://fhir-server', 'iss': 'test-issuer'}

        with pytest.raises(ValueError, match="Launch token missing required 'sub' field"):
            select_identity_provider(smart_service_with_patient_idps, launch_token)
