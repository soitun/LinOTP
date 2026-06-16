#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010-2019 KeyIdentity GmbH
#    Copyright (C) 2019-     netgo software GmbH
#
#    This file is part of LinOTP server.
#
#    This program is free software: you can redistribute it and/or
#    modify it under the terms of the GNU Affero General Public
#    License, version 3, as published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the
#               GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#
#    E-mail: info@linotp.de
#    Contact: www.linotp.org
#    Support: www.linotp.de
#


"""
Test FIDO2 token enrollment via /admin/init.
"""

from linotp.tests import TestController
from linotp.tests.functional.fido2_device import _AAGUID, SoftWebauthnDevice


class TestFido2AdminEnrollment(TestController):
    """Test FIDO2 token enrollment via admin/init (two-phase flow)."""

    def setUp(self):
        self.create_common_resolvers()
        self.create_common_realms()
        self._create_fido2_enrollment_policies()

    def tearDown(self):
        self.delete_all_policies()
        self.delete_all_token()
        self.delete_all_realms()
        self.delete_all_resolvers()

    def _create_fido2_enrollment_policies(self):
        """Set minimum policies needed for FIDO2 enrollment."""
        policy = {
            "name": "fido2_rpid",
            "scope": "enrollment",
            "action": "fido2_rp_id=localhost",
            "user": "*",
            "realm": "*",
            "active": True,
        }
        self.create_policy(policy)

    def test_enroll_fido2_with_user(self):
        """Two-phase FIDO2 enrollment via admin/init with a user assigned."""
        device = SoftWebauthnDevice()

        # Phase 1 — create the token and get registration challenge
        response = self.make_admin_request(
            "init",
            params={
                "type": "fido2",
                "user": "passthru_user1@myDefRealm",
            },
        )
        result = response.json["result"]
        assert result["status"] is True, response.json
        assert result["value"] is True, response.json

        detail = response.json["detail"]
        serial = detail["serial"]
        assert "registerrequest" in detail

        registerrequest = detail["registerrequest"]
        assert registerrequest["rp"]["id"] == "localhost"
        assert "challenge" in registerrequest
        assert registerrequest["user"]["name"] == "passthru_user1"

        # Phase 2 — answer the challenge with the software authenticator
        attestation_response = device.create(
            registerrequest, origin="https://localhost"
        )
        response = self.make_admin_request(
            "init",
            params={
                "serial": serial,
                "type": "fido2",
                "attestationResponse": attestation_response,
                "user": "passthru_user1@myDefRealm",
            },
            content_type="application/json",
        )
        result = response.json["result"]
        assert result["status"] is True, response.json
        assert result["value"] is True, response.json

        # Verify the token is now active and assigned
        response = self.make_admin_request(
            "show",
            params={"serial": serial},
        )
        token_data = response.json["result"]["value"]["data"][0]
        assert token_data["LinOtp.TokenType"] == "fido2"
        assert token_data["LinOtp.Isactive"] is True
        assert token_data["User.username"] == "passthru_user1"

    def test_enroll_fido2_without_user(self):
        """Two-phase FIDO2 enrollment via admin/init without a user."""
        device = SoftWebauthnDevice()

        # Phase 1 — create the token without assigning a user
        response = self.make_admin_request(
            "init",
            params={"type": "fido2"},
        )
        result = response.json["result"]
        assert result["status"] is True, response.json
        assert result["value"] is True, response.json

        detail = response.json["detail"]
        serial = detail["serial"]
        assert "registerrequest" in detail

        registerrequest = detail["registerrequest"]
        assert registerrequest["rp"]["id"] == "localhost"
        assert "challenge" in registerrequest
        # Without a user, WebAuthn user entity falls back to the serial
        assert registerrequest["user"]["name"] == serial

        # Phase 2 — answer the challenge with the software authenticator
        attestation_response = device.create(
            registerrequest, origin="https://localhost"
        )
        response = self.make_admin_request(
            "init",
            params={
                "serial": serial,
                "type": "fido2",
                "attestationResponse": attestation_response,
            },
            content_type="application/json",
        )
        result = response.json["result"]
        assert result["status"] is True, response.json
        assert result["value"] is True, response.json

        # Verify the token is now active and unassigned
        response = self.make_admin_request(
            "show",
            params={"serial": serial},
        )
        token_data = response.json["result"]["value"]["data"][0]
        assert token_data["LinOtp.TokenType"] == "fido2"
        assert token_data["LinOtp.Isactive"] is True
        assert token_data["User.username"] == ""

    def test_enroll_fido2_with_tokenrealm_policies(self):
        """Enrollment without user uses tokenrealm to resolve FIDO2 policies."""
        device = SoftWebauthnDevice()

        # Policies for myDefRealm — different values, should not be used
        policies_def_realm = [
            {
                "name": "fido2_rpid_def",
                "scope": "enrollment",
                "action": "fido2_rp_id=default.example.com",
                "user": "*",
                "realm": "myDefRealm",
                "active": True,
            },
            {
                "name": "fido2_rpname_def",
                "scope": "enrollment",
                "action": "fido2_rp_name=Default RP",
                "user": "*",
                "realm": "myDefRealm",
                "active": True,
            },
            {
                "name": "fido2_attestation_def",
                "scope": "enrollment",
                "action": "fido2_attestation_conveyance=none",
                "user": "*",
                "realm": "myDefRealm",
                "active": True,
            },
            {
                "name": "fido2_uv_def",
                "scope": "enrollment",
                "action": "fido2_user_verification_requirement=required",
                "user": "*",
                "realm": "myDefRealm",
                "active": True,
            },
            {
                "name": "fido2_rk_def",
                "scope": "enrollment",
                "action": "fido2_resident_key_requirement=required",
                "user": "*",
                "realm": "myDefRealm",
                "active": True,
            },
            {
                "name": "fido2_auth_types_def",
                "scope": "enrollment",
                "action": "fido2_authenticator_types=client-device",
                "user": "*",
                "realm": "myDefRealm",
                "active": True,
            },
        ]
        for p in policies_def_realm:
            self.create_policy(p)

        # Policies for myOtherRealm — these should be used
        policies_other_realm = [
            {
                "name": "fido2_rpid_other",
                "scope": "enrollment",
                "action": "fido2_rp_id=other.example.com",
                "user": "*",
                "realm": "myOtherRealm",
                "active": True,
            },
            {
                "name": "fido2_rpname_other",
                "scope": "enrollment",
                "action": "fido2_rp_name=Other RP",
                "user": "*",
                "realm": "myOtherRealm",
                "active": True,
            },
            {
                "name": "fido2_attestation_other",
                "scope": "enrollment",
                "action": "fido2_attestation_conveyance=direct",
                "user": "*",
                "realm": "myOtherRealm",
                "active": True,
            },
            {
                "name": "fido2_uv_other",
                "scope": "enrollment",
                "action": "fido2_user_verification_requirement=discouraged",
                "user": "*",
                "realm": "myOtherRealm",
                "active": True,
            },
            {
                "name": "fido2_rk_other",
                "scope": "enrollment",
                "action": "fido2_resident_key_requirement=discouraged",
                "user": "*",
                "realm": "myOtherRealm",
                "active": True,
            },
            {
                "name": "fido2_auth_types_other",
                "scope": "enrollment",
                "action": "fido2_authenticator_types=security-key",
                "user": "*",
                "realm": "myOtherRealm",
                "active": True,
            },
            {
                "name": "fido2_allowed_auth_other",
                "scope": "enrollment",
                "action": f"fido2_allowed_authenticators={_AAGUID}",
                "user": "*",
                "realm": "myOtherRealm",
                "active": True,
            },
        ]
        for p in policies_other_realm:
            self.create_policy(p)

        # Phase 1 — enroll without user, using tokenrealm=myOtherRealm
        response = self.make_admin_request(
            "init",
            params={
                "type": "fido2",
                # currently "realm" parameter is used to assign token to realm.
                "realm": "myOtherRealm",
            },
        )
        result = response.json["result"]
        assert result["status"] is True, response.json
        assert result["value"] is True, response.json

        detail = response.json["detail"]
        serial = detail["serial"]
        registerrequest = detail["registerrequest"]

        # Verify the realm-specific policies are reflected in the challenge
        assert registerrequest["rp"]["id"] == "other.example.com"
        assert registerrequest["rp"]["name"] == "Other RP"
        assert registerrequest["attestation"] == "direct"

        auth_sel = registerrequest["authenticatorSelection"]
        assert auth_sel["userVerification"] == "discouraged"
        assert auth_sel["residentKey"] == "discouraged"
        assert auth_sel["authenticatorAttachment"] == "cross-platform"
        assert registerrequest["hints"] == ["security-key"]

        attestation_response = device.create(
            registerrequest, origin="https://other.example.com"
        )
        response = self.make_admin_request(
            "init",
            params={
                "serial": serial,
                "type": "fido2",
                "realm": "myOtherRealm",
                "attestationResponse": attestation_response,
            },
            content_type="application/json",
        )
        result = response.json["result"]
        assert result["status"] is True, response.json
        assert result["value"] is True, response.json

    def test_enroll_fido2_tokenrealm_allowed_authenticators_rejected(self):
        """Enrollment fails when device AAGUID is not in tokenrealm's whitelist."""
        # Set a tokenrealm policy that only allows a different AAGUID
        self.create_policy(
            {
                "name": "fido2_rpid_other",
                "scope": "enrollment",
                "action": "fido2_rp_id=other.example.com",
                "user": "*",
                "realm": "myOtherRealm",
                "active": True,
            }
        )
        self.create_policy(
            {
                "name": "fido2_allowed_auth_other",
                "scope": "enrollment",
                "action": "fido2_allowed_authenticators=00000000-0000-0000-0000-000000000099",
                "user": "*",
                "realm": "myOtherRealm",
                "active": True,
            }
        )
        # myDefRealm allows the device's AAGUID — but it should not matter
        # because enrollment uses tokenrealm=myOtherRealm
        self.create_policy(
            {
                "name": "fido2_allowed_auth_def",
                "scope": "enrollment",
                "action": f"fido2_allowed_authenticators={_AAGUID}",
                "user": "*",
                "realm": "myDefRealm",
                "active": True,
            }
        )

        device = SoftWebauthnDevice()

        # Phase 1
        response = self.make_admin_request(
            "init",
            params={
                "type": "fido2",
                # currently "realm" parameter is used to assign token to realm.
                "realm": "myOtherRealm",
            },
        )
        assert response.json["result"]["status"] is True, response.json
        detail = response.json["detail"]
        serial = detail["serial"]

        # Phase 2 — should fail because the AAGUID doesn't match
        attestation_response = device.create(
            detail["registerrequest"], origin="https://other.example.com"
        )
        response = self.make_admin_request(
            "init",
            params={
                "serial": serial,
                "type": "fido2",
                "realm": "myOtherRealm",
                "attestationResponse": attestation_response,
            },
            content_type="application/json",
        )
        assert response.json["result"]["status"] is False, response.json
