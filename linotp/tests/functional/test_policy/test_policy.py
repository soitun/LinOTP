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


"""Test for various policy aspects:
- adminstrative permissions
- authorization
- authentication
- selfservice
- enrollment
"""

import copy
import logging
import re

import pytest

from . import TestPoliciesBase

log = logging.getLogger(__name__)


class TestPolicies(TestPoliciesBase):
    def setUp(self):
        """
        Overwrite the deleting of the realms!

        If the realms are deleted also the table TokenRealm gets deleted and
        we loose the information how many tokens are within a realm!
        """

        TestPoliciesBase.setUp(self)

    def tearDown(self):
        """Overwrite parent tear down, which removes all realms"""

    # define fixtures

    @pytest.fixture
    def realms_and_resolver(self):
        """Define the common resolvers and realms."""

        # ----------------------------------------------------------------- --
        # Policy 00: Init the tests and define the common resolver and realms
        # ----------------------------------------------------------------- --

        self.create_common_resolvers()
        self.create_common_realms()

    @pytest.fixture
    def admin_roles(self):
        """Define the superadmin and admin roles."""

        # ----------------------------------------------------------------- --
        # Policy 01: create a policy for the superadmin
        # ----------------------------------------------------------------- --

        parameters = {
            "name": "ManageAll",
            "scope": "admin",
            "realm": "*",
            "action": "*",
            "user": "superadmin, Administrator",
        }
        response = self.make_system_request(
            action="setPolicy", params=parameters, auth_user="superadmin"
        )
        assert response.json["result"]["status"], response

        # ----------------------------------------------------------------- --
        # Policy 02: create a policy for the realm admin
        # ----------------------------------------------------------------- --

        parameters = {
            "name": "ManageRealm1",
            "scope": "admin",
            "realm": "myDefRealm",
            "action": "*",
            "user": "adminR1, adminR2",
        }
        response = self.make_system_request(
            action="setPolicy", params=parameters, auth_user="superadmin"
        )

        assert response.json["result"]["status"], response

        # ----------------------------------------------------------------- --
        # Policy 03: Realm admin reads policies
        # ----------------------------------------------------------------- --

        parameters = {}
        response = self.make_system_request(
            action="getPolicy", params=parameters, auth_user="adminR1"
        )

        assert response.json["result"]["status"], response

        # ----------------------------------------------------------------- --
        # Policy 04: The superadmin is allowed to write to system and
        #              thus to set policies
        # ----------------------------------------------------------------- --

        parameters = {
            "name": "sysSuper",
            "scope": "system",
            "realm": "*",
            "action": "*",
            "user": "superadmin",
        }
        response = self.make_system_request(
            action="setPolicy", params=parameters, auth_user="superadmin"
        )

        assert response.json["result"]["status"], response

        # ----------------------------------------------------------------- --
        # Policy 05: The realmAdmin is allowed to read the system config
        # ----------------------------------------------------------------- --

        parameters = {
            "name": "sysRealms1Admin",
            "scope": "system",
            "realm": "*",
            "action": "read",
            "enforce": "true",
            "user": "adminR1",
        }
        response = self.make_system_request(
            action="setPolicy", params=parameters, auth_user="superadmin"
        )

        assert response.json["result"]["status"], response

        # ----------------------------------------------------------------- --
        # Policy 201: creating all the administrators (scope admin)
        #             with all necessary policies.
        # ----------------------------------------------------------------- --

        # one administrator for initialize
        parameters = {
            "name": "adm201",
            "scope": "admin",
            "realm": "*",
            "action": ("initSPASS, initHMAC, initETNG, initSMS, initMOTP, initOCRA2"),
            "user": "admin_init",
        }
        response = self.make_system_request(
            action="setPolicy", params=parameters, auth_user="superadmin"
        )

        assert response.json["result"]["status"], response
        # one administrator for enabling and disabling
        parameters = {
            "name": "adm201a",
            "scope": "admin",
            "realm": "*",
            "action": "enable, disable",
            "user": "admin_enable_disable",
        }
        response = self.make_system_request(
            action="setPolicy", params=parameters, auth_user="superadmin"
        )

        assert response.json["result"]["status"], response

        # one administrator for setting
        parameters = {
            "name": "adm201b",
            "scope": "admin",
            "realm": "*",
            "action": "set",
            "user": "admin_set",
        }
        response = self.make_system_request(
            action="setPolicy", params=parameters, auth_user="superadmin"
        )

        assert response.json["result"]["status"], response

        # one administrator for setting
        parameters = {
            "name": "adm201c",
            "scope": "admin",
            "realm": "*",
            "action": "setOTPPIN, setMOTPPIN, setOCRAPIN",
            "user": "admin_setpin",
        }
        response = self.make_system_request(
            action="setPolicy", params=parameters, auth_user="superadmin"
        )

        assert response.json["result"]["status"], response

        # one administrator for resyncing
        parameters = {
            "name": "adm201d",
            "scope": "admin",
            "realm": "*",
            "action": "resync",
            "user": "admin_resync",
        }
        response = self.make_system_request(
            action="setPolicy", params=parameters, auth_user="superadmin"
        )

        assert response.json["result"]["status"], response

        # one administrator for resetting
        parameters = {
            "name": "adm201e",
            "scope": "admin",
            "realm": "*",
            "action": "reset",
            "user": "admin_reset",
        }
        response = self.make_system_request(
            action="setPolicy", params=parameters, auth_user="superadmin"
        )

        assert response.json["result"]["status"], response

        # one administrator for removing
        parameters = {
            "name": "adm201f",
            "scope": "admin",
            "realm": "*",
            "action": "remove",
            "user": "admin_remove",
        }
        response = self.make_system_request(
            action="setPolicy", params=parameters, auth_user="superadmin"
        )

        assert response.json["result"]["status"], response

        # one administrator for removing
        parameters = {
            "name": "adm201g",
            "scope": "admin",
            "realm": "*",
            "action": "assign, unassign",
            "user": "admin_assign_unassign",
        }
        response = self.make_system_request(
            action="setPolicy", params=parameters, auth_user="superadmin"
        )

        assert response.json["result"]["status"], response

    @pytest.mark.usefixtures("realms_and_resolver", "admin_roles")
    def test_06setPolicy_System(self):
        """
        Policy 06: The adminEnroller is not allowed to read system
            obsolete, as this should happen implicit, as in test_05
            a system policy is already set and anybody else should now
            have no access to the system
        """

        parameters = {
            "name": "sysAdminEnroller",
            "scope": "system",
            "realm": "*",
            "action": "",
            "user": "adminEnroller",
        }
        response = self.make_system_request(
            action="setPolicy", params=parameters, auth_user="superadmin"
        )

        assert not response.json["result"]["status"], response
        assert "setPolicy failed: name and action required!" in response, response

    @pytest.mark.usefixtures("realms_and_resolver", "admin_roles")
    def test_07a_setPolicy_w_empty_action(self):
        """
        Policy 07a: The setting of a policy with an empty action is not allowed
        """

        parameters = {
            "name": "sysAdminEnroller",
            "scope": "system",
            "realm": "*",
            "action": "",
            "user": "adminEnroller",
        }
        response = self.make_system_request(
            action="setPolicy", params=parameters, auth_user="superadmin"
        )

        assert not response.json["result"]["status"], response
        assert "setPolicy failed: name and action required!" in response, response

    @pytest.mark.usefixtures("realms_and_resolver", "admin_roles")
    def test_07checkPolicy_System(self):
        """
        Policy 07: The realm Admin returns true, if he reads the system
        """
        parameters = {}
        response = self.make_system_request(
            action="getPolicy", params=parameters, auth_user="adminR1"
        )

        assert response.json["result"]["status"], response

    @pytest.mark.usefixtures("realms_and_resolver", "admin_roles")
    def test_08checkPolicy_System(self):
        """
        Policy 08: The realm Admin returns false, if he tries to write to system
        """
        parameters = {
            "name": "sysXXX",
            "scope": "system",
            "realm": "*",
            "action": "",
            "user": "neuerAdmin",
        }
        response = self.make_system_request(
            action="setPolicy", params=parameters, auth_user="adminR1"
        )

        assert not response.json["result"]["status"], response

    @pytest.mark.usefixtures("realms_and_resolver", "admin_roles")
    def test_09checkPolicy_System(self):
        """
        Policy 09: The enroller Admin returns false, if he tries to write to system
        """
        parameters = {
            "name": "sysXXX",
            "scope": "system",
            "realm": "*",
            "action": "",
            "user": "adminEnroller",
        }
        response = self.make_system_request(
            action="setPolicy", params=parameters, auth_user="adminEnroller"
        )

        assert not response.json["result"]["status"], response

    @pytest.mark.usefixtures("realms_and_resolver", "admin_roles")
    def test_10checkPolicy_System(self):
        """
        Policy 10: The enroller Admin returns false, if he tries to read to system
        """
        parameters = {}
        response = self.make_system_request(
            action="getPolicy", params=parameters, auth_user="adminEnroller"
        )

        assert not response.json["result"]["status"], response

    @pytest.fixture
    @pytest.mark.usefixtures("realms_and_resolver", "admin_roles")
    def enroll_tokens(self):
        """
        Policy 202: Init tokens in different with different admins
                    "admin_init" is allowed to do so, "admin_reset" not.
        """

        parameters = {
            "serial": "test_token_001",
            "type": "spass",
        }
        response = self.make_admin_request(
            action="init", params=parameters, auth_user="admin_init"
        )

        assert response.json["result"]["status"], response

        parameters = {
            "serial": "test_token_002",
            "type": "spass",
            "otpkey": "geheim",
        }
        response = self.make_admin_request(
            action="init", params=parameters, auth_user="admin_reset"
        )

        assert not response.json["result"]["status"], response

        parameters = {
            "serial": "test_token_003",
            "type": "spass",
            "otpkey": "geheim",
        }
        response = self.make_admin_request(
            action="init", params=parameters, auth_user="admin_init"
        )

        assert response.json["result"]["status"], response

        parameters = {
            "serial": "test_token_004",
            "user": "root@myDefRealm",
            "otpkey": "1234123412341234",
            "otppin": "1234",
        }
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="init", params=parameters, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        parameters = {
            "serial": "test_token_motp",
            "otpkey": "1234123412341234",
            "otppin": "m",
            "type": "mOTP",
        }
        response = self.make_admin_request(
            action="init", params=parameters, auth_user="admin_init"
        )

        assert response.json["result"]["status"], response

        params = {
            "serial": "test_token_ocra",
            "user": "horst",
            "type": "ocra2",
            "sharedsecret": "1",
            "genkey": "1",
            "ocrasuite": "OCRA-1:HOTP-SHA256-8:C-QN08",
        }

        response = self.make_admin_request("init", params, auth_user="admin_init")
        assert "false" not in response

    @pytest.mark.usefixtures("realms_and_resolver", "admin_roles", "enroll_tokens")
    def test_203_enable_disbale(self):
        """
        Policy 203: enabling and disabling tokens. "admin_enable_disable"
                    is allowed, "admin_init" not.
        """
        parameters = {
            "serial": "test_token_001",
        }
        response = self.make_admin_request(
            action="disable", params=parameters, auth_user="admin_init"
        )

        assert not response.json["result"]["status"], response

        parameters = {"serial": "test_token_001"}
        response = self.make_admin_request(
            action="disable",
            params=parameters,
            auth_user="admin_enable_disable",
        )

        assert response.json["result"]["status"], response

        parameters = {"serial": "test_token_001"}
        response = self.make_admin_request(
            action="enable", params=parameters, auth_user="admin_init"
        )

        assert not response.json["result"]["status"], response

        parameters = {"serial": "test_token_001"}
        response = self.make_admin_request(
            action="enable",
            params=parameters,
            auth_user="admin_enable_disable",
        )

        assert response.json["result"]["status"], response

    @pytest.mark.usefixtures("realms_and_resolver", "admin_roles", "enroll_tokens")
    def test_204_set(self):
        """
        Policy 204: setting token properties. "admin_set" is allowed,
                    "admin_init" not.
        """
        parameters = {
            "serial": "test_token_001",
            "maxFailCount": "20",
        }
        response = self.make_admin_request(
            action="set", params=parameters, auth_user="admin_init"
        )

        assert not response.json["result"]["status"], response

        parameters = {
            "serial": "test_token_001",
            "maxFailCount": "20",
        }
        response = self.make_admin_request(
            action="set", params=parameters, auth_user="admin_set"
        )

        assert response.json["result"]["status"], response

    @pytest.mark.usefixtures("realms_and_resolver", "admin_roles", "enroll_tokens")
    def test_205_setPIN(self):
        """
        Policy 205: setting PIN. "admin_setpin" is allowed, "admin_set" not!
        """
        parameters = {
            "serial": "test_token_motp",
            "userpin": "test",
        }
        response = self.make_admin_request(
            action="setPin", params=parameters, auth_user="admin_set"
        )

        assert not response.json["result"]["status"], response

        parameters = {
            "serial": "test_token_ocra",
            "userpin": "test",
        }
        response = self.make_admin_request(
            action="setPin", params=parameters, auth_user="admin_set"
        )

        assert not response.json["result"]["status"], response

        parameters = {
            "serial": "test_token_motp",
            "userpin": "test",
        }
        response = self.make_admin_request(
            action="setPin", params=parameters, auth_user="admin_setpin"
        )

        assert response.json["result"]["status"], response

        parameters = {
            "serial": "test_token_ocra",
            "userpin": "test",
        }
        response = self.make_admin_request(
            action="setPin", params=parameters, auth_user="admin_setpin"
        )

        assert response.json["result"]["status"], response

        parameters = {
            "serial": "test_token_001",
            "pin": "test",
        }
        response = self.make_admin_request(
            action="set", params=parameters, auth_user="admin_set"
        )

        assert not response.json["result"]["status"], response

        parameters = {
            "serial": "test_token_001",
            "pin": "test",
        }
        response = self.make_admin_request(
            action="set", params=parameters, auth_user="admin_setpin"
        )

        assert response.json["result"]["status"], response

    @pytest.mark.usefixtures("realms_and_resolver", "admin_roles", "enroll_tokens")
    def test_205_setPin_on_ocra_with_setMOTPPIN(self):
        """
        assure the setMOTPPIN policy cannot be used to set the userpin for the ocra token
        """
        setPolicyParams = {
            "name": "adm201c",
            "scope": "admin",
            "realm": "*",
            "action": "setOTPPIN, setMOTPPIN",
            "user": "admin_setpin",
        }
        response = self.make_system_request(
            action="setPolicy", params=setPolicyParams, auth_user="superadmin"
        )

        assert response.json["result"]["status"], response

        parameters = {
            "serial": "test_token_ocra",
            "userpin": "test",
        }
        response = self.make_admin_request(
            action="setPin", params=parameters, auth_user="admin_setpin"
        )

        assert not response.json["result"]["status"], response

    @pytest.mark.usefixtures("realms_and_resolver", "admin_roles", "enroll_tokens")
    def test_206_resync(self):
        """
        Policy 206: resynching token. "admin_resync" is allowed.
                    "admin_set" not.
        """
        parameters = {
            "serial": "test_token_001",
            "otp1": "123456",
            "otp2": "123456",
        }
        response = self.make_admin_request(
            action="resync", params=parameters, auth_user="admin_set"
        )

        assert not response.json["result"]["status"], response

        parameters = {
            "serial": "test_token_001",
            "otp1": "123456",
            "otp2": "123456",
        }

        response = self.make_admin_request(
            action="resync", params=parameters, auth_user="admin_resync"
        )

        assert response.json["result"]["status"], response

    @pytest.mark.usefixtures("realms_and_resolver", "admin_roles", "enroll_tokens")
    def test_207_reset(self):
        """
        Policy 207: admin is allowed to reset a token
        """

        parameters = {"serial": "test_token_001"}
        response = self.make_admin_request(
            action="reset", params=parameters, auth_user="admin_set"
        )

        assert not response.json["result"]["status"], response

        parameters = {"serial": "test_token_001"}
        response = self.make_admin_request(
            action="reset", params=parameters, auth_user="admin_reset"
        )

        assert response.json["result"]["status"], response

    @pytest.mark.usefixtures("realms_and_resolver", "admin_roles", "enroll_tokens")
    def test_208_assign_unassign(self):
        """
        Policy 208: admin_assign_unassign is allowed to assign and unassign
                    a token. admin_set is not allowed to assign
        """

        parameters = {"serial": "test_token_001", "user": "root"}
        response = self.make_admin_request(
            action="assign", params=parameters, auth_user="admin_set"
        )

        assert not response.json["result"]["status"], response

        parameters = {"serial": "test_token_001", "user": "root"}
        response = self.make_admin_request(
            action="assign",
            params=parameters,
            auth_user="admin_assign_unassign",
        )

        assert response.json["result"]["status"], response

        parameters = {"serial": "test_token_001"}
        response = self.make_admin_request(
            action="unassign",
            params=parameters,
            auth_user="admin_assign_unassign",
        )

        assert response.json["result"]["status"], response

    @pytest.mark.usefixtures("realms_and_resolver", "admin_roles", "enroll_tokens")
    def test_209_remove_fail(self):
        """
        Policy 209: test remove fail
        """
        parameters = {"serial": "test_token_003"}
        response = self.make_admin_request(
            action="remove", params=parameters, auth_user="admin_set"
        )

        assert not response.json["result"]["status"], response

    @pytest.mark.usefixtures("realms_and_resolver", "admin_roles", "enroll_tokens")
    def test_210_remove_success(self):
        """
        Policy 210: test remove success
        """
        parameters = {"serial": "test_token_001"}
        response = self.make_admin_request(
            action="remove", params=parameters, auth_user="admin_remove"
        )

        assert response.json["result"]["status"], response

    @pytest.mark.usefixtures("realms_and_resolver", "admin_roles", "enroll_tokens")
    def test_211_remove_in_wrong_realm(self):
        """
        Policy 211: An administrator is not allowed to remove a token,
                    if the token is in the wrong realm
        """
        policy = "pol211"
        admin = "admin211"
        realm = "realm211"
        realm_wrong = "realmwrong211"
        serial = "spass211"
        params = {
            "name": policy,
            "scope": "admin",
            "action": "initHMAC, remove",
            "user": admin,
            "realm": realm,
        }

        response = self.make_system_request(
            action="setPolicy", params=params, auth_user="superadmin"
        )

        assert response.json["result"]["status"], response
        assert response.json["result"]["value"]["setPolicy pol211"], response

        # add token to realm_wrong
        params = {
            "serial": serial,
            "type": "spass",
        }
        response = self.make_admin_request(
            action="init", params=params, auth_user="superadmin"
        )

        assert response.json["result"]["status"], response
        assert response.json["result"]["value"], response

        params = {
            "serial": serial,
            "realms": realm_wrong,
        }
        response = self.make_admin_request(
            action="tokenrealm", params=params, auth_user="superadmin"
        )

        assert response.json["result"]["status"], response
        assert response.json["result"]["value"] == 1, response

        # admin will fail to remove token in wrong realm
        params = {"serial": serial}
        response = self.make_admin_request(
            action="remove", params=params, auth_user=admin
        )

        assert not response.json["result"]["status"], response
        message = "You do not have the administrative right to remove token"
        assert message in response.json["result"]["error"]["message"], response

        # remove token
        params = {"serial": serial}
        response = self.make_admin_request(
            action="remove", params=params, auth_user="superadmin"
        )

        assert response.json["result"]["status"], response
        assert response.json["result"]["value"] == 1, response

        # remove policy
        params = {
            "name": policy,
        }
        response = self.make_system_request(
            action="delPolicy", params=params, auth_user="superadmin"
        )

        assert response.json["result"]["status"], response
        values = set(response.json["result"]["value"]["delPolicy"]["result"].values())
        assert False not in values, response

    @pytest.mark.usefixtures("realms_and_resolver", "admin_roles", "enroll_tokens")
    def test_212_remove_no_action(self):
        """
        Policy 212: admin is not allowed to remove token, if he does not have
                    the action in the right realm
        """
        policy = "pol212"
        admin = "admin212"
        realm = "realm212"
        serial = "spass212"

        # add token to realm_wrong
        params = {
            "name": policy,
            "scope": "admin",
            "action": "initHMAC, initSPASS",
            "user": admin,
            "realm": realm,
        }

        response = self.make_system_request(
            action="setPolicy", params=params, auth_user="superadmin"
        )

        assert response.json["result"]["status"], response
        assert response.json["result"]["value"]["setPolicy pol212"], response

        # add token to realm_wrong
        params = {"serial": serial, "type": "spass"}

        response = self.make_admin_request(
            action="init", params=params, auth_user="superadmin"
        )

        assert response.json["result"]["status"], response
        assert response.json["result"]["value"], response

        params = {
            "serial": serial,
            "realms": realm,
        }
        response = self.make_admin_request(
            action="tokenrealm", params=params, auth_user="superadmin"
        )

        assert response.json["result"]["status"], response
        assert response.json["result"]["value"] == 1, response

        # admin will fail to remove token in his right realm
        params = {"serial": serial}
        response = self.make_admin_request(
            action="remove", params=params, auth_user=admin
        )

        assert not response.json["result"]["status"], response
        msg = "ERR410: You do not have the administrative right to remove token"
        assert msg in response.json["result"]["error"]["message"], response

        # remove token
        params = {"serial": serial}
        response = self.make_admin_request(
            action="remove", params=params, auth_user="superadmin"
        )

        assert response.json["result"]["status"], response
        assert response.json["result"]["value"] == 1, response

        # remove policy
        params = {"name": policy}
        response = self.make_system_request(
            action="delPolicy", params=params, auth_user="superadmin"
        )

        assert response.json["result"]["status"], response
        values = set(response.json["result"]["value"]["delPolicy"]["result"].values())
        assert False not in values

    @pytest.mark.usefixtures("realms_and_resolver", "admin_roles", "enroll_tokens")
    def test_213_remove_no_realm(self):
        """
        Policy 213: An administrator is not allowed to remove a token,
                    if the token is in NO realm
        """
        policy = "pol213"
        admin = "admin213"
        realm = "realm213"
        serial = "spass213"

        params = {
            "name": policy,
            "scope": "admin",
            "action": "initHMAC, remove",
            "user": admin,
            "realm": realm,
        }
        response = self.make_system_request(
            action="setPolicy", params=params, auth_user="superadmin"
        )

        assert response.json["result"]["status"], response
        assert response.json["result"]["value"]["setPolicy pol213"], response

        # token has no realm
        params = {"serial": serial, "type": "spass"}
        response = self.make_admin_request(
            action="init", params=params, auth_user="superadmin"
        )

        assert response.json["result"]["status"], response
        assert response.json["result"]["value"], response

        # admin will fail to remove the token as it is in no realm of his
        params = {"serial": serial}
        response = self.make_admin_request(
            action="remove", params=params, auth_user=admin
        )

        assert not response.json["result"]["status"], response
        msg = "You do not have the administrative right to remove token"
        assert msg in response.json["result"]["error"]["message"], response

        # remove token
        params = {"serial": serial}
        response = self.make_admin_request(
            action="remove", params=params, auth_user="superadmin"
        )

        assert response.json["result"]["status"], response
        assert response.json["result"]["value"] == 1, response

        # remove policy
        params = {"name": policy}
        response = self.make_system_request(
            action="delPolicy", params=params, auth_user="superadmin"
        )

        assert response.json["result"]["status"], response
        values = set(response.json["result"]["value"]["delPolicy"]["result"].values())
        assert False not in values, response

        # TODO: check different REALMS, manageRealms usw.

    @pytest.mark.usefixtures("realms_and_resolver", "admin_roles")
    def test_31_set_support_subscription(self):
        """
        Policy 31: Check for a user not allowed to set the support subscription
        """
        parameters = {}
        response = self.make_system_request(
            action="setSupport", params=parameters, auth_user="adminEnroller"
        )

        assert not response.json["result"]["status"], response

    @pytest.mark.usefixtures("realms_and_resolver", "admin_roles")
    def test_32_set_support_subscription(self):
        """
        Policy 32: Check if the user superadmin is allowed to set the support
                   subscription
        """
        parameters = {}
        response = self.make_system_request(
            action="setSupport", params=parameters, auth_user="superadmin"
        )

        msg = "No key 'license' in the upload request"
        assert msg in response.json["result"]["error"]["message"], response

    @pytest.fixture
    @pytest.mark.usefixtures("realms_and_resolver", "admin_roles")
    def selfservice_policies(self):
        """Define a set of selfservice policies."""

        # ----------------------------------------------------------------- --
        # Policy 41: Test several self service policies
        # ----------------------------------------------------------------- --

        parameters = {
            "name": "self_01",
            "scope": "selfservice",
            "realm": "myDefRealm",
            "action": "enrollSMS, enrollMOTP, assign",
        }
        response = self.make_system_request(
            action="setPolicy", params=parameters, auth_user="superadmin"
        )

        assert response.json["result"]["status"], response

        parameters = {
            "name": "self_02",
            "scope": "selfservice",
            "realm": "myOtherRealm",
            "action": "enrollMOTP, disable, resync, setOTPPIN, setMOTPPIN",
        }
        response = self.make_system_request(
            action="setPolicy", params=parameters, auth_user="superadmin"
        )

        assert response.json["result"]["status"], response

        parameters = {
            "name": "self_03",
            "scope": "selfservice",
            "realm": "myMixRealm",
            "action": "enrollHMAC",
        }
        response = self.make_system_request(
            action="setPolicy", params=parameters, auth_user="superadmin"
        )

        assert response.json["result"]["status"], response

        # ----------------------------------------------------------------- --
        # Policy 420: test enrolling of tokens in the selfservice portal
        # ----------------------------------------------------------------- --

        parameters = {
            "type": "motp",
            "serial": "self001",
            "otpkey": "1234123412341234",
            "otppin": "1234",
        }
        auth_user = ("horst@myDefRealm", "test123")
        response = self.make_userservice_request(
            action="enroll", params=parameters, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        parameters = {
            "type": "motp",
            "serial": "self002",
            "otpkey": "1234123412341234",
            "otppin": "1234",
            "pin": "",
        }
        auth_user = ("postgres@myOtherRealm", "test123")
        response = self.make_userservice_request(
            action="enroll", params=parameters, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        # ----------------------------------------------------------------- --
        # Users in myMixRealm are not allowed to init a token
        # ----------------------------------------------------------------- --

        parameters = {
            "type": "motp",
            "serial": "self003",
            "otpkey": "1234123412341234",
            "otppin": "1234",
        }
        auth_user = ("horst@myMixRealm", "test123")
        response = self.make_userservice_request(
            action="enroll", params=parameters, auth_user=auth_user
        )

        assert not response.json["result"]["status"], response

    # ----------------------------------------------------------------- --
    # Check the self services
    # ----------------------------------------------------------------- --

    @pytest.mark.usefixtures(
        "realms_and_resolver",
        "admin_roles",
        "selfservice_policies",
        "enroll_tokens",
    )
    def test_421_selfService_disable(self):
        """
        Policy 421: Test disabling tokens in the selfservice portal
        """

        # myDefRealm is not allowed to disable
        parameters = {"serial": "self001"}
        auth_user = ("horst@myMixRealm", "test123")
        response = self.make_userservice_request(
            action="disable", params=parameters, auth_user=auth_user
        )

        assert not response.json["result"]["status"], response

        # myOtherRealm is allowed to disable
        parameters = {"serial": "self002"}
        auth_user = ("postgres@myOtherRealm", "test123")
        response = self.make_userservice_request(
            action="disable", params=parameters, auth_user=auth_user
        )

        assert response.json["result"]["value"]["disable token"] == 1, response

        # myOtherRealm: a user, not the owner of the token can not
        # disable the token
        parameters = {"serial": "self002"}
        auth_user = ("b1822@myOtherRealm", "test123")
        response = self.make_userservice_request(
            action="disable", params=parameters, auth_user=auth_user
        )

        assert response.json["result"]["status"], response
        assert response.json["result"]["value"] == {}, response

    @pytest.mark.usefixtures(
        "realms_and_resolver",
        "admin_roles",
        "selfservice_policies",
        "enroll_tokens",
    )
    def test_422_sefService_setOTPPIN(self):
        """
        Policy 422: Test setting PIN in the selfserivce portal
        """
        # myDefRealm is not allowed to disable
        parameters = {"serial": "self001", "userpin": "test"}
        auth_user = ("horst@myDefRealm", "test123")

        response = self.make_userservice_request(
            action="setpin", params=parameters, auth_user=auth_user
        )

        assert not response.json["result"]["status"], response

        # myOtherRealm is allowed to set PIN
        parameters = {"serial": "self002", "userpin": "test"}
        auth_user = ("postgres@myOtherRealm", "test123")
        response = self.make_userservice_request(
            action="setpin", params=parameters, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        parameters = {"serial": "self001"}
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="remove", params=parameters, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        parameters = {"serial": "self002"}
        auth_user = "superadmin"

        response = self.make_admin_request(
            action="remove", params=parameters, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

    @pytest.mark.usefixtures(
        "realms_and_resolver",
        "admin_roles",
        "selfservice_policies",
        "enroll_tokens",
    )
    def test_423a_selfservice_assign(self):
        """
        Policy 423a: users in myDefRealm are allowed to assign. use the token
                     test_token_003
        """
        parameters = {"serial": "test_token_003", "realms": "myDefRealm"}
        auth_user = "superadmin"

        response = self.make_admin_request(
            action="tokenrealm", params=parameters, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        response = self.make_admin_request(
            action="show", params={}, auth_user=auth_user
        )

        token_found = False
        tokens = response.json["result"]["value"]["data"]
        for token in tokens:
            if token["LinOtp.TokenSerialnumber"] == "test_token_003":
                assert token["LinOtp.CountWindow"] == 10, token
                assert token["LinOtp.MaxFail"] == 10, token
                assert token["User.description"] == "", token
                assert token["LinOtp.IdResClass"] == "", token
                assert token["LinOtp.RealmNames"][0] == "mydefrealm", token
                token_found = True

        assert token_found

        parameters = {"serial": "test_token_003"}
        auth_user = ("horst@myDefRealm", "test123")
        response = self.make_userservice_request(
            action="assign", params=parameters, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        # unassign the token
        parameters = {"serial": "test_token_003"}
        auth_user = "superadmin"

        response = self.make_admin_request(
            action="unassign", params=parameters, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

    @pytest.mark.usefixtures(
        "realms_and_resolver",
        "admin_roles",
        "selfservice_policies",
        "enroll_tokens",
    )
    def test_424_selfservice_assign(self):
        """
        Policy 424: user in myOtherRealm may not assign token
        """
        parameters = {"serial": "test_token_003", "realms": "myOtherRealm"}
        auth_user = "superadmin"

        response = self.make_admin_request(
            action="tokenrealm", params=parameters, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        # user tries to assign
        parameters = {"serial": "test_token_003"}
        auth_user = ("b1822@myOtherRealm", "test123")
        response = self.make_userservice_request(
            action="assign", params=parameters, auth_user=auth_user
        )

        assert not response.json["result"]["status"], response

    @pytest.mark.usefixtures(
        "realms_and_resolver",
        "admin_roles",
        "selfservice_policies",
        "enroll_tokens",
    )
    def test_425_selfservice_user(self):
        """
        Policy 425: check a user dependent policy
        """
        params = {
            "name": "self_user_pol1",
            "scope": "selfservice",
            "realm": "myDefRealm",
            "user": "user1",
            "action": "enrollHMAC",
        }
        auth_user = "superadmin"

        response = self.make_system_request(
            action="setPolicy", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        # user in realm, who has no policy
        parameters = {"type": "hmac"}
        auth_user = ("user2@myDefRealm", "geheim2")
        response = self.make_userservice_request(
            action="enroll", params=parameters, auth_user=auth_user
        )

        assert not response.json["result"]["status"], response

        # user who has a policy
        parameters = {"type": "hmac"}
        auth_user = ("user1@myDefRealm", "geheim1")
        response = self.make_userservice_request(
            action="enroll", params=parameters, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        # delete the policy
        params = {"name": "self_user_pol1"}
        auth_user = "superadmin"

        response = self.make_system_request(
            action="delPolicy", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        # delete both tokens
        params = {"user": "user1"}
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="remove", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        params = {"user": "user2"}
        auth_user = "superadmin"

        response = self.make_admin_request(
            action="remove", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

    @pytest.mark.usefixtures(
        "realms_and_resolver",
        "admin_roles",
        "selfservice_policies",
        "enroll_tokens",
    )
    def test_426_selfservice_resolver(self):
        """
        Policy 426: check a resolver dependent policy
        """
        params = {
            "name": "self_res_pol1",
            "scope": "selfservice",
            "realm": "myMixRealm",
            "user": "myDefRes:",
            "action": "enrollHMAC",
        }
        auth_user = "superadmin"
        response = self.make_system_request(
            action="setPolicy", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        # delete the old self_03 policy, so that we can use
        # the mixrealm to test
        params = {"name": "self_03"}
        auth_user = "superadmin"

        response = self.make_system_request(
            action="delPolicy", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        # we list all the policy to find errors
        params = {"scope": "selfservice", "realm": "mymixrealm"}
        auth_user = "superadmin"
        response = self.make_system_request(
            action="getPolicy", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        # user in resolver myOtherRes, who is not allowed to enroll token
        parameters = {"type": "hmac"}
        auth_user = ("max1@myMixRealm", "password1")
        response = self.make_userservice_request(
            action="enroll", params=parameters, auth_user=auth_user
        )

        assert not response.json["result"]["status"], response

        # user in resolver myDefRes, who is allowed to enroll token
        parameters = {"type": "hmac"}
        auth_user = ("user1@myMixRealm", "geheim1")
        response = self.make_userservice_request(
            action="enroll", params=parameters, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        # delete the policy
        params = {"name": "self_res_pol1"}
        auth_user = "superadmin"
        response = self.make_system_request(
            action="delPolicy", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        # delete both tokens
        params = {"user": "user1"}
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="remove", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        params = {"user": "user2"}
        auth_user = "superadmin"

        response = self.make_admin_request(
            action="remove", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

    @pytest.mark.usefixtures(
        "realms_and_resolver",
        "admin_roles",
        "selfservice_policies",
        "enroll_tokens",
    )
    def test_427_selfservice_assign(self):
        """
        Policy 427: user in realm myDefRealm assignes a token, that is
                    not contained in any realm
        """
        serial = "temp_spass_427"
        parameters = {
            "serial": serial,
            "type": "spass",
            "pin": "something",
        }
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="init", params=parameters, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        # check this token is in no realm
        response = self.make_admin_request(
            action="show", params={}, auth_user=auth_user
        )

        token_found = False
        tokens = response.json["result"]["value"]["data"]
        for token in tokens:
            if token["LinOtp.TokenSerialnumber"] == serial:
                assert token["LinOtp.CountWindow"] == 10, token
                assert token["LinOtp.MaxFail"] == 10, token
                assert token["User.description"] == "", token
                assert token["LinOtp.IdResClass"] == "", token
                assert token["LinOtp.RealmNames"] == [], token
                token_found = True

        assert token_found

        # user tries to assign
        parameters = {"serial": serial}
        auth_user = ("horst@myDefRealm", "test123")

        response = self.make_userservice_request(
            action="assign", params=parameters, auth_user=auth_user
        )

        assert response.json["result"]["value"]["assign token"], response

        params = {"serial": serial}
        response = self.make_admin_request(
            action="remove", params=params, auth_user="superadmin"
        )

        assert response.json["result"]["value"] == 1, response

    @pytest.mark.usefixtures(
        "realms_and_resolver",
        "admin_roles",
        "selfservice_policies",
        "enroll_tokens",
    )
    def test_428_selfservice_assign(self):
        """
        Policy 428: user in realm myDefRealm can not assign a token that
                    is contained in another realm
        """
        serial = "temp_spass_428"
        parameters = {
            "serial": serial,
            "type": "spass",
            "pin": "something",
        }
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="init", params=parameters, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        # set the realm of the token
        params = {"serial": serial, "realms": "myOtherRealm"}
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="tokenrealm", params=params, auth_user=auth_user
        )

        assert response.json["result"]["value"] == 1, response

        # check this token is in no realm
        params = {"serial": serial}
        response = self.make_admin_request(
            action="show", params=params, auth_user=auth_user
        )

        token_found = False
        tokens = response.json["result"]["value"]["data"]
        for token in tokens:
            if token["LinOtp.TokenSerialnumber"] == "temp_spass_428":
                assert token["LinOtp.CountWindow"] == 10, token
                assert token["LinOtp.MaxFail"] == 10, token
                assert token["User.description"] == "", token
                assert token["LinOtp.IdResClass"] == "", token
                assert "myotherrealm" in token["LinOtp.RealmNames"], token
                token_found = True

        assert token_found

        # user tries to assign
        parameters = {"serial": serial}
        auth_user = ("horst@myDefRealm", "test123")
        response = self.make_userservice_request(
            action="assign", params=parameters, auth_user=auth_user
        )

        assert not response.json["result"]["status"], response
        assert (
            "The token you want to assign is not contained in your realm!" in response
        ), response

        params = {"serial": serial}
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="remove", params=params, auth_user=auth_user
        )

        assert response.json["result"]["value"] == 1, response

    @pytest.mark.usefixtures(
        "realms_and_resolver",
        "admin_roles",
        "selfservice_policies",
        "enroll_tokens",
    )
    def test_429_get_serial_by_OTP(self):
        """
        Policy 429: get serial by OTP value
        """
        # TODO
        seed = "154bf508c52f3048fcf9cf721bbb892637f5e348"
        otps = ["295354", "297395", "027303", "618651"]

        serial = "oath429"
        parameters = {
            "serial": serial,
            "type": "hmac",
            "otpkey": seed,
            "pin": "something",
        }
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="init", params=parameters, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        # set the realm of the token
        params = {"serial": serial, "realms": "myDefRealm"}
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="tokenrealm", params=params, auth_user=auth_user
        )

        assert response.json["result"]["value"] == 1, response

        # check this token is in no realm
        params = {"serial": serial}
        response = self.make_admin_request(
            action="show", params=params, auth_user=auth_user
        )

        token_found = False
        tokens = response.json["result"]["value"]["data"]
        for token in tokens:
            if token["LinOtp.TokenSerialnumber"] == "oath429":
                token_found = True

        assert token_found, tokens

        # user to get the serial of the OTP of the unassigned token.
        parameters = {
            "otp": otps[3],
        }
        auth_user = ("passthru_user1@myDefRealm", "geheim1")
        response = self.make_userservice_request(
            action="getSerialByOtp", params=parameters, auth_user=auth_user
        )

        assert not response.json["result"]["status"], response
        assert (
            "The policy settings do not allow you to request a "
            "serial by OTP!" in response
        ), response

        # set policy
        params = {
            "name": "getSerial",
            "scope": "selfservice",
            "realm": "myDefRealm",
            "action": "getserial",
        }
        auth_user = "superadmin"
        response = self.make_system_request(
            action="setPolicy", params=params, auth_user=auth_user
        )

        assert response.json["result"]["value"], response

        # try again to get the serial
        parameters = {"otp": otps[0], "realm": "myDefRealm"}
        auth_user = ("passthru_user1@myDefRealm", "geheim1")
        response = self.make_userservice_request(
            action="getSerialByOtp", params=parameters, auth_user=auth_user
        )

        assert response.json["result"]["status"], response
        assert response.json["result"]["value"]["serial"] == "oath429", response

        parameters = {"otp": otps[3]}
        auth_user = ("passthru_user1@myDefRealm", "geheim1")
        response = self.make_userservice_request(
            action="getSerialByOtp", params=parameters, auth_user=auth_user
        )

        assert response.json["result"]["status"], response
        assert response.json["result"]["value"]["serial"] == "oath429", response

        # remove the policy
        params = {"name": "getSerial"}
        auth_user = "superadmin"
        response = self.make_system_request(
            action="delPolicy", params=params, auth_user=auth_user
        )

        assert response.json["result"]["value"], response

        # remove the token
        params = {"serial": serial}
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="remove", params=params, auth_user=auth_user
        )

        assert response.json["result"]["value"] == 1, response

    @pytest.mark.usefixtures("realms_and_resolver", "admin_roles", "enroll_tokens")
    def test_430_passthru_policy(self):
        """
        Policy 430: check the passthru policy. passthru_user1/geheim1 is
                    allowed, passthru_user2/geheim2 is not.
        """
        params = {
            "name": "passthru",
            "scope": "authentication",
            "realm": "myDefRealm",
            "user": "passthru_user1",
            "action": "passthru",
        }
        auth_user = "superadmin"
        response = self.make_system_request(
            action="setPolicy", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        # user1 is allowed to passthru as he has no token.
        params = {"user": "passthru_user1", "pass": "geheim1"}
        response = self.make_validate_request(action="check", params=params)

        assert response.json["result"]["value"], response

        # user2 is allowed to passthru as he is not in the policy
        params = {"user": "passthru_user2", "pass": "geheim2"}
        response = self.make_validate_request(action="check", params=params)

        assert not response.json["result"]["value"], response

        params = {"name": "NoToken"}
        auth_user = "superadmin"

        response = self.make_system_request(
            action="delPolicy", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

    @pytest.mark.usefixtures("realms_and_resolver", "admin_roles", "enroll_tokens")
    def test_430_passOnNoToken_policy(self):
        """
        Policy 430: check the passOnNoToken policy. passthru_user1 is
                    allowed with any password, passthru_user2/geheim2 is not.
        """
        params = {
            "name": "NoToken",
            "scope": "authentication",
            "realm": "myDefRealm",
            "user": "passthru_user1",
            "action": "passOnNoToken",
        }
        auth_user = "superadmin"

        response = self.make_system_request(
            action="setPolicy", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        # user1 is allowed to passthru as he has no token.
        params = {"user": "passthru_user1", "pass": "argsargs"}
        response = self.make_validate_request(action="check", params=params)

        assert response.json["result"]["value"], response

        params = {"user": "passthru_user1", "pass": "OtherPW"}
        response = self.make_validate_request(action="check", params=params)

        assert response.json["result"]["value"], response

        # user2 is allowed to passthru as he is not in the policy
        params = {"user": "passthru_user2", "pass": "geheim2"}
        response = self.make_validate_request(action="check", params=params)

        assert not response.json["result"]["value"], response

        params = {"name": "NoToken"}
        auth_user = "superadmin"
        response = self.make_system_request(
            action="delPolicy", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

    @pytest.mark.usefixtures("realms_and_resolver", "admin_roles", "enroll_tokens")
    def test_431_otppin_policy(self):
        """
        Policy 431: check that passthru_user1 can authenticate with the
                    password but passthru_user2 authenticates with OTP PIN.
        """
        params = {
            "name": "otppin",
            "scope": "authentication",
            "realm": "myDefRealm",
            "user": "passthru_user1",
            "action": "otppin=1",
        }
        auth_user = "superadmin"

        response = self.make_system_request(
            action="setPolicy", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        # enroll a token for each user
        params = {
            "user": "passthru_user1",
            "type": "spass",
            "serial": "spass_pin_1",
            "pin": "otppin",
        }
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="init", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        params = {
            "user": "passthru_user2",
            "type": "spass",
            "serial": "spass_pin_2",
            "pin": "otppin",
        }
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="init", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        # user1 has otppin=1
        params = {"user": "passthru_user1", "pass": "geheim1"}
        response = self.make_validate_request(action="check", params=params)

        assert response.json["result"]["value"], response

        # user2 has default otppin=0
        params = {"user": "passthru_user2", "pass": "geheim2"}
        response = self.make_validate_request(action="check", params=params)

        assert not response.json["result"]["value"], response

        params = {"user": "passthru_user2", "pass": "otppin"}
        response = self.make_validate_request(action="check", params=params)

        assert response.json["result"]["value"], response

        params = {"name": "otppin"}
        auth_user = "superadmin"

        response = self.make_system_request(
            action="delPolicy", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        # remove the tokens
        params = {"serial": "spass_pin_2"}
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="remove", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        params = {"serial": "spass_pin_1"}
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="remove", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

    @pytest.mark.usefixtures("realms_and_resolver", "admin_roles", "enroll_tokens")
    def test_440_check_authorize(self):
        """
        Policy 440: check if a user is authorized (scope=authorization)
                    to login from  a certain client
        """
        params = {
            "name": "authorize_user1",
            "scope": "authorization",
            "realm": "myDefRealm",
            "user": "passthru_user1",
            "action": "authorize",
            "client": "192.168.17.15",
        }
        auth_user = "superadmin"

        response = self.make_system_request(
            action="setPolicy", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        # enroll a token for each user
        params = {
            "user": "passthru_user1",
            "type": "spass",
            "serial": "spass_pin_1",
            "pin": "otppin",
        }
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="init", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        params = {
            "user": "passthru_user2",
            "type": "spass",
            "serial": "spass_pin_2",
            "pin": "otppin",
        }
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="init", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        # auth user 1
        params = {"user": "passthru_user1", "pass": "otppin"}
        client = "192.168.17.15"
        response = self.make_validate_request(
            action="check", params=params, client=client
        )

        assert response.json["result"]["value"], response

        # auth user 1 fails. Wrong client
        params = {"user": "passthru_user1", "pass": "otppin"}
        client = "192.168.17.16"
        response = self.make_validate_request(
            action="check", params=params, client=client
        )

        assert not response.json["result"]["value"], response

        # user2 is not allowed to auth
        params = {"user": "passthru_user2", "pass": "otppin"}
        client = "192.168.17.15"
        response = self.make_validate_request(
            action="check", params=params, client=client
        )

        assert not response.json["result"]["value"], response

        # user2 may login at other clients
        params = {"user": "passthru_user2", "pass": "otppin"}
        client = "192.168.17.16"
        response = self.make_validate_request(
            action="check", params=params, client=client
        )

        assert not response.json["result"]["value"], response

        # now test for this user a second wildcard policy
        params = {
            "name": "authorize_user2",
            "scope": "authorization",
            "realm": "myDefRealm",
            "user": "passthru_user2",
            "action": "authorize",
            "client": "*",
        }
        auth_user = "superadmin"
        response = self.make_system_request(
            action="setPolicy", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        # user2 may login at other clients
        params = {"user": "passthru_user2", "pass": "otppin"}
        client = "192.168.17.16"
        response = self.make_validate_request(
            action="check", params=params, client=client
        )

        assert response.json["result"]["value"], response

        # delete the policy
        params = {"name": "authorize_user1"}
        auth_user = "superadmin"
        response = self.make_system_request(
            action="delPolicy", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        params = {"name": "authorize_user2"}
        auth_user = "superadmin"
        response = self.make_system_request(
            action="delPolicy", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        # remove the tokens
        params = {"serial": "spass_pin_2"}
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="remove", params=params, auth_user=auth_user
        )
        assert response.json["result"]["status"], response

        params = {"serial": "spass_pin_1"}
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="remove", params=params, auth_user=auth_user
        )
        assert response.json["result"]["status"], response

    @pytest.mark.usefixtures("realms_and_resolver", "admin_roles", "enroll_tokens")
    def test_440a_check_authorize_client_exclude(self):
        """
        Policy 440a: check if authorize policy honor the excluded clients
        """
        params = {
            "name": "authorize_root",
            "scope": "authorization",
            "realm": "myDefRealm",
            "user": "passthru_user1",
            "action": "authorize",
            "client": "192.168.17.15, 192.168.17.16",
        }
        auth_user = "superadmin"
        response = self.make_system_request(
            action="setPolicy", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        params = {
            "name": "authorize_all",
            "scope": "authorization",
            "realm": "myDefRealm",
            "user": "*",
            "action": "authorize",
            "client": "192.168.0.0/16, -192.168.17.15, !192.168.17.16",
        }
        auth_user = "superadmin"
        response = self.make_system_request(
            action="setPolicy", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        # enroll a token for each user
        params = {
            "user": "passthru_user1",
            "type": "spass",
            "serial": "spass_pin_1",
            "pin": "otppin",
        }
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="init", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        params = {
            "user": "passthru_user2",
            "type": "spass",
            "serial": "spass_pin_2",
            "pin": "otppin",
        }
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="init", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        # auth user 1
        params = {"user": "passthru_user1", "pass": "otppin"}
        client = "192.168.17.15"
        response = self.make_validate_request(
            action="check", params=params, client=client
        )

        assert response.json["result"]["value"], response

        # auth user 1 can also auth on othe clients
        params = {"user": "passthru_user1", "pass": "otppin"}
        client = "192.168.20.1"

        response = self.make_validate_request(
            action="check", params=params, client=client
        )

        assert response.json["result"]["value"], response

        # user2 is not allowed to auth on certain clients
        params = {"user": "passthru_user2", "pass": "otppin"}
        client = "192.168.17.15"
        response = self.make_validate_request(
            action="check", params=params, client=client
        )

        assert not response.json["result"]["value"], response

        params = {"user": "passthru_user2", "pass": "otppin"}
        client = "192.168.17.16"
        response = self.make_validate_request(
            action="check", params=params, client=client
        )

        assert not response.json["result"]["value"], response

        # user2 may login at other clients
        params = {"user": "passthru_user2", "pass": "otppin"}
        client = "192.168.20.1"
        response = self.make_validate_request(
            action="check", params=params, client=client
        )

        assert response.json["result"]["value"], response

        # delete the policy

        params = {"name": "authorize_root"}
        auth_user = "superadmin"
        response = self.make_system_request(
            action="delPolicy", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        params = {"name": "authorize_all"}
        auth_user = "superadmin"
        response = self.make_system_request(
            action="delPolicy", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        # remove the tokens
        params = {"serial": "spass_pin_2"}
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="remove", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        params = {"serial": "spass_pin_1"}
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="remove", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

    @pytest.mark.usefixtures("realms_and_resolver", "admin_roles", "enroll_tokens")
    def test_441_check_tokentype(self):
        """
        Policy 441: check the authorization token type.
            User with tokentype PW may login, tokentype SPASS may not
        """
        params = {
            "name": "authorize_user1",
            "scope": "authorization",
            "realm": "myDefRealm",
            "user": "passthru_user1",
            "action": "tokentype=PW",
            "client": "192.168.20.21",
        }
        auth_user = "superadmin"
        response = self.make_system_request(
            action="setPolicy", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        # enroll a token for each user
        params = {
            "user": "passthru_user1",
            "type": "spass",
            "serial": "spass_pin_1",
            "pin": "otppin",
        }
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="init", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        # Token type SPASS is not allowed to login
        params = {"user": "passthru_user1", "pass": "otppin"}
        client = "192.168.20.21"
        response = self.make_validate_request(
            action="check", params=params, client=client
        )

        assert not response.json["result"]["value"], response

        # Token type SPASS is allowed to login from another client
        params = {"user": "passthru_user1", "pass": "otppin"}
        client = "192.168.20.22"
        response = self.make_validate_request(
            action="check", params=params, client=client
        )

        assert response.json["result"]["value"], response

        # delete old token SPASS and enroll PW token
        params = {"serial": "spass_pin_1"}
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="remove", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        params = {
            "user": "passthru_user1",
            "type": "pw",
            "serial": "pw_1",
            "pin": "otppin",
            "otpkey": "secret",
        }
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="init", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        # Token type PW is allowed to login
        params = {"user": "passthru_user1", "pass": "otppinsecret"}
        client = "192.168.20.21"
        response = self.make_validate_request(
            action="check", params=params, client=client
        )

        assert response.json["result"]["value"], response

        # delete PW token
        params = {"serial": "pw_1"}
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="remove", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        #
        # enroll PW token for passthru_user2
        #
        params = {
            "user": "passthru_user2",
            "type": "spass",
            "serial": "spass_2",
            "pin": "otppin",
        }
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="init", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        # user 2 can authenticate with other token, since he is not in policy
        params = {"user": "passthru_user2", "pass": "otppin"}
        client = "192.168.20.21"
        response = self.make_validate_request(
            action="check", params=params, client=client
        )

        assert response.json["result"]["value"], response

        # delete pw_2
        params = {"serial": "spass_2"}
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="remove", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        # delete the policy
        params = {"name": "authorize_user1"}
        auth_user = "superadmin"
        response = self.make_system_request(
            action="delPolicy", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

    @pytest.mark.usefixtures("realms_and_resolver", "admin_roles", "enroll_tokens")
    def test_441b_check_auth_serial(self):
        """
        Policy 441b: check the authorization serial.
            User with serial  may login, tokentype SPASS may not
        """
        params = {
            "name": "authorize_user1",
            "scope": "authorization",
            "realm": "myDefRealm",
            "user": "passthru_user1",
            "action": "serial=^pw.*",
            "client": "192.168.20.21",
        }
        auth_user = "superadmin"
        response = self.make_system_request(
            action="setPolicy", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        # enroll a token for each user
        params = {
            "user": "passthru_user1",
            "type": "spass",
            "serial": "spass_pin_1",
            "pin": "otppin",
        }
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="init", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        # Token type SPASS is not allowed to login
        params = {"user": "passthru_user1", "pass": "otppin"}
        client = "192.168.20.21"
        response = self.make_validate_request(
            action="check", params=params, client=client
        )

        assert not response.json["result"]["value"], response

        # Token type SPASS is allowed to login from another client
        params = {"user": "passthru_user1", "pass": "otppin"}
        client = "192.168.20.22"
        response = self.make_validate_request(
            action="check", params=params, client=client
        )

        assert response.json["result"]["value"], response

        # delete old token SPASS and enroll PW token
        params = {"serial": "spass_pin_1"}
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="remove", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        params = {
            "user": "passthru_user1",
            "type": "pw",
            "serial": "pw_1",
            "pin": "otppin",
            "otpkey": "secret",
        }
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="init", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        # Token type PW is allowed to login
        params = {"user": "passthru_user1", "pass": "otppinsecret"}
        client = "192.168.20.21"
        response = self.make_validate_request(
            action="check", params=params, client=client
        )

        assert response.json["result"]["value"], response

        # delete PW token
        params = {"serial": "pw_1"}
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="remove", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        #
        # enroll PW token for passthru_user2
        #
        params = {
            "user": "passthru_user2",
            "type": "spass",
            "serial": "spass_2",
            "pin": "otppin",
        }
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="init", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        # user 2 can authenticate with other token, since he is not in policy
        params = {"user": "passthru_user2", "pass": "otppin"}
        client = "192.168.20.21"
        response = self.make_validate_request(
            action="check", params=params, client=client
        )

        assert response.json["result"]["value"], response

        # delete pw_2
        params = {"serial": "spass_2"}
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="remove", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        # delete the policy
        params = {"name": "authorize_user1"}
        auth_user = "superadmin"
        response = self.make_system_request(
            action="delPolicy", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

    @pytest.mark.usefixtures("realms_and_resolver", "admin_roles", "enroll_tokens")
    def test_442_set_realm(self):
        """
        Policy 442: set the realm during authentication for a given user
        """
        params = {
            "name": "set_realm",
            "scope": "authorization",
            "realm": "WrongRealm",
            "user": "passthru_user1",
            "action": "setrealm=myDefRealm",
            "client": "192.168.20.21",
        }
        auth_user = "superadmin"
        response = self.make_system_request(
            action="setPolicy", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        # enroll a token for each user
        params = {
            "user": "passthru_user1",
            "type": "spass",
            "serial": "spass_pin_1",
            "pin": "otppin",
        }
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="init", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        params = {
            "user": "passthru_user2",
            "type": "spass",
            "serial": "spass_pin_2",
            "pin": "otppin",
        }

        auth_user = "superadmin"
        response = self.make_admin_request(
            action="init", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        # Realm for user1 gets rewritten
        params = {"user": "passthru_user1@WrongRealm", "pass": "otppin"}
        client = "192.168.20.21"
        response = self.make_validate_request(
            action="check", params=params, client=client
        )

        assert response.json["result"]["value"], response

        # Realm for user2 gets not rewritten
        params = {"user": "passthru_user2@WrongRealm", "pass": "otppin"}
        client = "192.168.20.21"
        response = self.make_validate_request(
            action="check", params=params, client=client
        )

        assert not response.json["result"]["value"], response

        # User 2 can login with right realm
        params = {"user": "passthru_user2@myDefRealm", "pass": "otppin"}
        client = "192.168.20.21"
        response = self.make_validate_request(
            action="check", params=params, client=client
        )

        assert response.json["result"]["value"], response

        # delete the tokens
        params = {"serial": "spass_pin_1"}
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="remove", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        params = {"serial": "spass_pin_2"}
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="remove", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        # delete the policy
        params = {"name": "set_realm"}
        auth_user = "superadmin"
        response = self.make_system_request(
            action="delPolicy", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

    @pytest.fixture
    @pytest.mark.usefixtures("realms_and_resolver", "admin_roles")
    def userlist_admins(self):
        """
        Policy 501: check the userlisting for admins. Set up the policies
        """

        parameters = {
            "name": "501_user1",
            "scope": "admin",
            "realm": "MyDefRealm",
            "user": "501_admin_def",
            "action": "userlist",
        }
        auth_user = "superadmin"
        response = self.make_system_request(
            action="setPolicy", params=parameters, auth_user=auth_user
        )

        pkey = "setPolicy {}".format(parameters.get("name"))
        values = set(response.json["result"]["value"][pkey].values())
        assert False not in values, response

        parameters = {
            "name": "501_user2",
            "scope": "admin",
            "realm": "MyOtherRealm",
            "user": "501_admin_other",
            "action": "userlist",
        }
        auth_user = "superadmin"
        response = self.make_system_request(
            action="setPolicy", params=parameters, auth_user=auth_user
        )

        pkey = "setPolicy {}".format(parameters.get("name"))
        values = set(response.json["result"]["value"][pkey].values())
        assert False not in values, response

    @pytest.mark.usefixtures("realms_and_resolver", "admin_roles", "userlist_admins")
    def test_502_check_userlist(self):
        """
        Policy 502: check the userlisting rights. Userlisting allowed
        """
        parameters = {"realm": "MyDefRealm"}
        auth_user = "501_admin_def"
        response = self.make_admin_request(
            action="userlist", params=parameters, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        parameters = {"realm": "MyDefRealm", "sortname": "username", "rp": 30}
        auth_user = "501_admin_def"
        response = self.make_manage_request(
            action="userview_flexi", params=parameters, auth_user=auth_user
        )

        assert '"rows":' in response, response
        assert len(response.json["result"]["value"]["rows"]) == 27

    @pytest.mark.usefixtures("realms_and_resolver", "admin_roles", "userlist_admins")
    def test_503_check_userlist(self):
        """
        Policy 503: check the userlisting rights. Userlisting forbidden
        """

        parameters = {"realm": "MyDefRealm"}
        auth_user = "501_admin_other"
        response = self.make_admin_request(
            action="userlist", params=parameters, auth_user=auth_user
        )

        assert "You do not have the administrative right to list users" in response, (
            response
        )

        parameters = {"realm": "MyDefRealm"}
        auth_user = "501_admin_other"
        response = self.make_manage_request(
            action="userview_flexi", params=parameters, auth_user=auth_user
        )

        assert "You do not have the administrative right to list users" in response, (
            response
        )

    @pytest.mark.usefixtures("realms_and_resolver", "admin_roles")
    def test_550_check_policy(self):
        """
        Policy 550: Test the policy checker.
        """
        policies = [
            {
                "name": "cp1",
                "scope": "admin",
                "user": "cp1_admin",
                "realm": "realm1",
                "action": "*",
            },
            {
                "name": "cp2",
                "scope": "admin",
                "user": "cp2_admin",
                "realm": "realm1",
                "action": "remove",
            },
            {
                "name": "cp_enroll_1",
                "scope": "enrollment",
                "user": "user1",
                "action": "maxtoken=3",
                "realm": "myDefRealm",
            },
            {
                "name": "cp_enroll_2",
                "scope": "enrollment",
                "user": "",
                "action": "maxtoken=1",
                "realm": "myDefRealm",
            },
            {
                "name": "cp_auth_1",
                "scope": "authentication",
                "user": "user1",
                "action": "otppin=0",
                "realm": "myDefRealm",
            },
            {
                "name": "cp_auth_2",
                "scope": "authentication",
                "user": "",
                "action": "otppin=1",
                "realm": "myDefRealm",
            },
            {
                "name": "cp_self_1",
                "scope": "selfservice",
                "user": "user1",
                "action": "enrollHMAC, setOTPPIN",
                "realm": "myDefRealm",
            },
            {
                "name": "cp_self_2",
                "scope": "selfservice",
                "user": "user1",
                "action": "enrollHMAC, setOTPPIN, enrollTOTP",
                "realm": "myDefRealm",
                "client": "172.16.200.10",
            },
            {
                "name": "cp_self_3",
                "scope": "selfservice",
                "user": "",
                "action": "enrollHMAC",
                "realm": "myDefRealm",
            },
        ]

        # set the policies
        for pol in policies:
            auth_user = "superadmin"
            response = self.make_system_request(
                action="setPolicy", params=pol, auth_user=auth_user
            )

            assert response.json["result"]["status"], response

        # check the policies
        # cp1_admin is allowed to do all actions in realm1
        params = {
            "user": "cp1_admin",
            "realm": "realm1",
            "action": "initHMAC",
            "scope": "admin",
            "client": "",
        }
        auth_user = "superadmin"
        response = self.make_system_request(
            action="checkPolicy", params=params, auth_user=auth_user
        )
        assert '"cp1": {' in response, response
        assert '"allowed": true' in response, response

        # cp1_admin has no rights in realm2
        params = {
            "user": "cp1_admin",
            "realm": "realm2",
            "action": "initHMAC",
            "scope": "admin",
            "client": "",
        }
        auth_user = "superadmin"
        response = self.make_system_request(
            action="checkPolicy", params=params, auth_user=auth_user
        )

        assert '"allowed": false' in response, response

        # cp2_admin is allowed to remove in realm2
        params = {
            "user": "cp2_admin",
            "realm": "realm1",
            "action": "remove",
            "scope": "admin",
            "client": "",
        }
        auth_user = "superadmin"
        response = self.make_system_request(
            action="checkPolicy", params=params, auth_user=auth_user
        )

        assert '"cp2": {' in response, response
        assert '"allowed": true' in response, response

        # cp2_admin is not allowed to enroll in realm2
        params = {
            "user": "cp2_admin",
            "realm": "realm1",
            "action": "initHMAC",
            "scope": "admin",
            "client": "",
        }
        auth_user = "superadmin"
        response = self.make_system_request(
            action="checkPolicy", params=params, auth_user=auth_user
        )

        assert '"allowed": false' in response, response

        # check scope enrollment, user1 may enroll 3 tokens, user2 only 1 token
        params = {
            "user": "user1",
            "realm": "myDefRealm",
            "action": "maxtoken",
            "scope": "enrollment",
            "client": "",
        }
        auth_user = "superadmin"
        response = self.make_system_request(
            action="checkPolicy", params=params, auth_user=auth_user
        )

        assert '"cp_enroll_1": {' in response, response
        assert '"action": "maxtoken=3",' in response, response

        params = {
            "user": "user2",
            "realm": "myDefRealm",
            "action": "maxtoken",
            "scope": "enrollment",
            "client": "",
        }
        auth_user = "superadmin"
        response = self.make_system_request(
            action="checkPolicy", params=params, auth_user=auth_user
        )

        assert '"cp_enroll_2": {' in response, response
        assert '"action": "maxtoken=1",' in response, response

        # check scope authentication
        # user1 has otppin=0, all other suers otppin=1
        params = {
            "user": "user1",
            "realm": "myDefRealm",
            "action": "otppin",
            "scope": "authentication",
            "client": "",
        }
        auth_user = "superadmin"
        response = self.make_system_request(
            action="checkPolicy", params=params, auth_user=auth_user
        )

        assert '"cp_auth_1": {' in response, response
        assert '"action": "otppin=0",' in response, response

        params = {
            "user": "user2",
            "realm": "myDefRealm",
            "action": "otppin",
            "scope": "authentication",
            "client": "",
        }
        auth_user = "superadmin"
        response = self.make_system_request(
            action="checkPolicy", params=params, auth_user=auth_user
        )

        assert '"cp_auth_2": {' in response, response
        assert '"action": "otppin=1",' in response, response

        # check scope selfservice
        # enrollTOTP from 192.168.20.1 is not allowed
        params = {
            "user": "user1",
            "realm": "myDefRealm",
            "action": "enrollTOTP",
            "scope": "selfservice",
            "client": "192.168.20.1",
        }
        auth_user = "superadmin"
        response = self.make_system_request(
            action="checkPolicy", params=params, auth_user=auth_user
        )

        assert '"allowed": false' in response, response

        params = {
            "user": "user1",
            "realm": "myDefRealm",
            "action": "enrollHMAC",
            "scope": "selfservice",
            "client": "192.168.20.1",
        }
        auth_user = "superadmin"
        response = self.make_system_request(
            action="checkPolicy", params=params, auth_user=auth_user
        )

        assert '"allowed": true' in response, response
        assert '"action": "enrollHMAC, setOTPPIN",' in response, response

        # enrollTOTP from 172.16.200.X is allowed
        params = {
            "user": "user1",
            "realm": "myDefRealm",
            "action": "enrollTOTP",
            "scope": "selfservice",
            "client": "172.16.200.10",
        }
        auth_user = "superadmin"
        response = self.make_system_request(
            action="checkPolicy", params=params, auth_user=auth_user
        )

        assert '"cp_self_2": {' in response, response
        assert '"action": "enrollHMAC, setOTPPIN, enrollTOTP",' in response, response

        # delete the policies
        for policy in policies:
            params = {"name": policy["name"]}
            auth_user = "superadmin"
            response = self.make_system_request(
                action="delPolicy", params=params, auth_user=auth_user
            )

            assert response.json["result"]["status"], response

    @pytest.fixture
    @pytest.mark.usefixtures("realms_and_resolver", "admin_roles", "enroll_tokens")
    def otppin_policies(self):
        """
        Policy 601: set policy to allow setting OTP PIN
        """
        parameters = {
            "name": "self_01",
            "scope": "selfservice",
            "realm": "myDefRealm",
            "action": "setOTPPIN",
        }
        auth_user = "superadmin"
        response = self.make_system_request(
            action="setPolicy", params=parameters, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        parameters = {
            "name": "self_pin01",
            "scope": "selfservice",
            "realm": "myDefRealm",
            "action": "otp_pin_maxlength=8, otp_pin_minlength=4 ",
        }
        auth_user = "superadmin"
        response = self.make_system_request(
            action="setPolicy", params=parameters, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

    @pytest.mark.usefixtures(
        "realms_and_resolver",
        "admin_roles",
        "enroll_tokens",
        "otppin_policies",
    )
    def test_604_otp_length_do(self):
        """
        Policy 604: test the otp length
        """
        # PIN to short
        parameters = {"serial": "test_token_004", "userpin": "bla"}
        auth_user = ("root@myDefRealm", "test123")
        response = self.make_userservice_request(
            action="setpin", params=parameters, auth_user=auth_user
        )

        assert not response.json["result"]["status"], response

        # PIN to long
        parameters = {"serial": "test_token_004", "userpin": "12345678test"}
        auth_user = ("root@myDefRealm", "test123")
        response = self.make_userservice_request(
            action="setpin", params=parameters, auth_user=auth_user
        )

        assert not response.json["result"]["status"], response

        # PIN perfect
        parameters = {"serial": "test_token_004", "userpin": "1234567"}
        auth_user = ("root@myDefRealm", "test123")
        response = self.make_userservice_request(
            action="setpin", params=parameters, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

    @pytest.fixture
    @pytest.mark.usefixtures("realms_and_resolver", "admin_roles", "enroll_tokens")
    def otppin_contents(self):
        """
        Policy 605: testing contents of pin: set policy contents=c
        """
        parameters = {
            "name": "self_pin02",
            "scope": "selfservice",
            "realm": "myDefRealm",
            "action": "otp_pin_contents=c",
        }
        auth_user = "superadmin"
        response = self.make_system_request(
            action="setPolicy", params=parameters, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        """
        Policy 606: testing contents of pin: wrong pin
        """
        # PIN wrong
        parameters = {"serial": "test_token_004", "userpin": "123456"}
        auth_user = ("root@myDefRealm", "test123")
        response = self.make_userservice_request(
            action="setpin", params=parameters, auth_user=auth_user
        )

        assert not response.json["result"]["status"], response

    @pytest.mark.usefixtures(
        "realms_and_resolver",
        "admin_roles",
        "enroll_tokens",
        "otppin_policies",
        "otppin_contents",
    )
    def test_607_otppin_contents(self):
        """
        Policy 607: testing contents of pin: PIN ok
        """
        # PIN OK
        parameters = {"serial": "test_token_004", "userpin": "ab3456"}
        auth_user = ("root@myDefRealm", "test123")
        response = self.make_userservice_request(
            action="setpin", params=parameters, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

    @pytest.mark.usefixtures(
        "realms_and_resolver",
        "admin_roles",
        "enroll_tokens",
        "otppin_policies",
        "otppin_contents",
    )
    def test_608_otppin_contents(self):
        """
        Policy 608: testing contents of pin: contents=cns
        """
        parameters = {
            "name": "self_pin02",
            "scope": "selfservice",
            "realm": "myDefRealm",
            "action": "otp_pin_contents=cns",
        }
        auth_user = "superadmin"
        response = self.make_system_request(
            action="setPolicy", params=parameters, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

    @pytest.mark.usefixtures(
        "realms_and_resolver",
        "admin_roles",
        "enroll_tokens",
        "otppin_contents",
    )
    def test_609_otppin_contents(self):
        """
        Policy 609: testing contents of pin: wrong pin
        """
        # PIN wrong
        parameters = {"serial": "test_token_004", "userpin": "ab3456"}
        auth_user = ("root@myDefRealm", "test123")
        response = self.make_userservice_request(
            action="setpin", params=parameters, auth_user=auth_user
        )

        assert not response.json["result"]["status"], response

    @pytest.mark.usefixtures(
        "realms_and_resolver",
        "admin_roles",
        "enroll_tokens",
        "otppin_policies",
        "otppin_contents",
    )
    def test_610_otppin_contents(self):
        """
        Policy 610: testing contents of pin: PIN ok
        """
        parameters = {
            "serial": "test_token_004",
            "userpin": "ab3456!!",
        }
        auth_user = ("root@myDefRealm", "test123")
        response = self.make_userservice_request(
            action="setpin", params=parameters, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        # We would also need to define enrollment policies.
        # This will be done in the selfservice test script

    @pytest.mark.usefixtures("realms_and_resolver", "admin_roles", "enroll_tokens")
    def test_700_enrollment(self):
        """
        Policy 700: Enrollment policies
        """

        # ----------------------------------------------------------------- --
        # Policy 701: testing enrollment settings: Token limit per user: 2,
        #             tokens per realm 5. Setting policy
        # ----------------------------------------------------------------- --

        parameters = {
            "name": "enrollment_01",
            "scope": "enrollment",
            "realm": "myDefRealm",
            "action": "maxtoken=2, tokencount=3, otp_pin_random =4",
        }
        auth_user = "superadmin"
        response = self.make_system_request(
            action="setPolicy", params=parameters, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        # ----------------------------------------------------------------- --
        # Policy 702: Unassigning user root@myDefRealm and deleting all tokens
        #             from myDefRealm.
        # ----------------------------------------------------------------- --

        for t in ["test_token_003", "test_token_004"]:
            parameters = {"serial": t}
            auth_user = "superadmin"
            response = self.make_admin_request(
                action="remove", params=parameters, auth_user=auth_user
            )

            assert response.json["result"]["status"], response

        # ----------------------------------------------------------------- --
        # Policy 703: testing enrollment: the first two tokens will enroll,
        #             the 3rd will complain as the user may not own a 3rd token!
        # ----------------------------------------------------------------- --

        # now assign tokens
        parameters = {
            "serial": "enroll_001",
            "type": "spass",
            "user": "root@myDefRealm",
        }
        auth_user = "admin_init"
        response = self.make_admin_request(
            action="init", params=parameters, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        parameters = {
            "type": "spass",
            "user": "root@myDefRealm",
        }
        auth_user = "admin_init"
        response = self.make_admin_request(
            action="init", params=parameters, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        # The user may not own a third token!
        parameters = {
            "serial": "enroll_003",
            "type": "spass",
            "user": "root@myDefRealm",
        }
        auth_user = "admin_init"
        response = self.make_admin_request(
            action="init", params=parameters, auth_user=auth_user
        )

        assert not response.json["result"]["status"], response

        # ----------------------------------------------------------------- --
        # Policy 704: enroll the 3rd token in myDefRealm. The 4th token will
        #             complain, as tokencount = 3
        #
        # This was defined in test_701_enrollment
        # ----------------------------------------------------------------- --

        parameters = {
            "serial": "enroll_003",
            "type": "spass",
            "user": "remoteuser@myDefRealm",
        }
        auth_user = "admin_init"
        response = self.make_admin_request(
            action="init", params=parameters, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        # this would be the 4th token, but only 3 allowed.
        parameters = {
            "serial": "enroll_004",
            "type": "spass",
            "user": "remoteuser@myDefRealm",
        }
        auth_user = "admin_init"
        response = self.make_admin_request(
            action="init", params=parameters, auth_user=auth_user
        )

        assert not response.json["result"]["status"], response
        msg = "You can not init any more tokens"
        assert msg in response.json["result"]["error"]["message"], response

        # ----------------------------------------------------------------- --
        # Policy 705: create a new token enroll_tc_01 and try to assign this
        #             token to an user in the realm. Assigning will fail, since
        #             realm is full
        # ----------------------------------------------------------------- --

        parameters = {
            "serial": "enroll_tc_01",
            "otpkey": "e56eb2bcbafb2eea9bce9463f550f86d587d6c71",
            "description": "my EToken",
        }
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="init", params=parameters, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        parameters = {
            "serial": "enroll_tc_01",
            "user": "remoteuser@myDefRealm",
        }
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="assign", params=parameters, auth_user=auth_user
        )

        assert not response.json["result"]["status"], response
        # assert 'You can not assign any more tokens' in response

        # ----------------------------------------------------------------- --
        # Policy 706: Try to set the tokenrealm of the token enroll_tc_01 to the
        #             realm "myDefRealm". Will fail, since realm is full
        # ----------------------------------------------------------------- --

        parameters = {
            "serial": "enroll_tc_01",
            "realms": "mydefrealm",
        }
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="tokenrealm", params=parameters, auth_user=auth_user
        )

        assert not response.json["result"]["status"], response
        msg = "You may not put any more tokens in realm"
        assert msg in response.json["result"]["error"]["message"], response

        # ----------------------------------------------------------------- --
        # Policy 707: Try to enable a token in a full realm. Will fail,
        #             since realm is full
        # ----------------------------------------------------------------- --

        parameters = {"serial": "enroll_003"}
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="disable", params=parameters, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        parameters = {"serial": "enroll_tc_01", "realms": "mydefrealm"}
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="tokenrealm", params=parameters, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        parameters = {"serial": "enroll_003"}
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="enable", params=parameters, auth_user=auth_user
        )

        assert not response.json["result"]["status"], response
        assert "You may not enable any more tokens in realm" in response, response

        # ----------------------------------------------------------------- --
        # Policy 709: Testing maxtoken per user. Policy will be applied for
        #             defined user, not for not defined user
        #             We take myOtherRealm, since for myDefRealm already a
        #             maxtoken-policy exist
        # ----------------------------------------------------------------- --

        params = {
            "name": "maxtoken_per_user",
            "scope": "enrollment",
            "realm": "myOtherRealm",
            "user": "max1",
            "action": "maxtoken=1",
            "client": "",
        }
        auth_user = "superadmin"
        response = self.make_system_request(
            action="setPolicy", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        # enroll a token max1
        params = {
            "user": "max1",
            "realm": "myOtherRealm",
            "type": "spass",
            "serial": "spass_pin_1",
            "pin": "otppin",
        }
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="init", params=params, auth_user=auth_user
        )

        assert response.json["result"]["value"], response

        # enroll 2nd token for max1 will fail
        params = {
            "user": "max1",
            "realm": "myOtherRealm",
            "type": "spass",
            "serial": "spass_pin_2",
            "pin": "otppin",
        }
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="init", params=params, auth_user=auth_user
        )

        assert "maximum number of allowed tokens per user is exceeded" in response, (
            response
        )

        # enroll 2 tokens for max2
        params = {
            "user": "max2",
            "realm": "myOtherRealm",
            "type": "spass",
            "serial": "spass_pin_3",
            "pin": "otppin",
        }
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="init", params=params, auth_user=auth_user
        )

        assert response.json["result"]["value"], response

        params = {
            "user": "max2",
            "realm": "myOtherRealm",
            "type": "spass",
            "serial": "spass_pin_4",
            "pin": "otppin",
        }
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="init", params=params, auth_user=auth_user
        )

        assert response.json["result"]["value"], response

        # delete the tokens of the user
        for serial in ["spass_pin_1", "spass_pin_3", "spass_pin_4"]:
            params = {"serial": serial}
            auth_user = "superadmin"
            response = self.make_admin_request(
                action="remove", params=params, auth_user=auth_user
            )

            assert response.json["result"]["status"], response

        # delete the policy
        params = {"name": "maxtoken_per_user"}
        auth_user = "superadmin"
        response = self.make_system_request(
            action="delPolicy", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

    @pytest.mark.usefixtures("realms_and_resolver", "admin_roles")
    def test_710_otp_pin_random_for_users(self):
        """
        Policy 710: Testing scope=enrollment, otp_pin_random for
                    different users
        """
        params = {
            "name": "otppinrandom_per_user",
            "scope": "enrollment",
            "realm": "myOtherRealm",
            "user": "max1",
            "action": "otp_pin_random=4",
            "client": "",
        }
        auth_user = "superadmin"
        response = self.make_system_request(
            action="setPolicy", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        # enroll a token max1
        params = {
            "user": "max1",
            "realm": "myOtherRealm",
            "type": "spass",
            "serial": "spass_pin_1",
            "pin": "otppin",
        }
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="init", params=params, auth_user=auth_user
        )

        assert response.json["result"]["value"], response

        # enroll token for max2
        params = {
            "user": "max2",
            "realm": "myOtherRealm",
            "type": "spass",
            "serial": "spass_pin_2",
            "pin": "otppin",
        }
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="init", params=params, auth_user=auth_user
        )

        assert response.json["result"]["value"], response

        # validate token of max1: unknown otp pin
        params = {"user": "max1", "realm": "myOtherRealm", "pass": "otppin"}
        response = self.make_validate_request(action="check", params=params)

        assert not response.json["result"]["value"], response

        # validate token of max2: known otp pin
        params = {"user": "max2", "realm": "myOtherRealm", "pass": "otppin"}
        response = self.make_validate_request(action="check", params=params)

        assert response.json["result"]["value"], response

        # delete the tokens of the user
        for serial in ["spass_pin_1", "spass_pin_2"]:
            params = {"serial": serial}
            auth_user = "superadmin"
            response = self.make_admin_request(
                action="remove", params=params, auth_user=auth_user
            )

            assert response.json["result"]["status"], response

        # delete the policy
        params = {"name": "otppinrandom_per_user"}
        auth_user = "superadmin"
        response = self.make_system_request(
            action="delPolicy", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

    @pytest.mark.usefixtures("realms_and_resolver", "admin_roles")
    def test_711_get_tokenlabel_for_users(self):
        """
        Policy 711: Testing scope=enrollment, tokenlabel/tokenissuer
                    for different users
        """
        params = {
            "name": "tokenlabel_per_user",
            "scope": "enrollment",
            "realm": "myOtherRealm",
            "user": "max1",
            "action": "tokenlabel=<u>",
            "client": "",
        }
        auth_user = "superadmin"
        response = self.make_system_request(
            action="setPolicy", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        # enroll a token max1
        params = {
            "user": "max1",
            "realm": "myOtherRealm",
            "serial": "hmac1",
            "type": "hmac",
            "genkey": 1,
        }
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="init", params=params, auth_user=auth_user
        )

        enrollment_url = response.json["detail"]["enrollment_url"]["value"]
        assert "otpauth://hotp/LinOTP:max1?" in enrollment_url, response

        googleurl = response.json["detail"]["googleurl"]["value"]
        assert "otpauth://hotp/LinOTP:max1?" in googleurl, response

        # enroll token for max2
        params = {
            "user": "max2",
            "realm": "myOtherRealm",
            "serial": "hmac2",
            "type": "hmac",
            "genkey": 1,
        }
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="init", params=params, auth_user=auth_user
        )

        enrollment_url = response.json["detail"]["enrollment_url"]["value"]
        assert "otpauth://hotp/LinOTP:max2?" in enrollment_url, response

        googleurl = response.json["detail"]["googleurl"]["value"]
        assert "otpauth://hotp/LinOTP:max2?" in googleurl, response

        # add tokenissuer policy
        params = {
            "name": "tokenissuer_with_realm",
            "scope": "enrollment",
            "realm": "myOtherRealm",
            "user": "max1",
            "action": "tokenissuer=fakeissuer-<r>",
            "client": "",
        }
        auth_user = "superadmin"
        response = self.make_system_request(
            action="setPolicy", params=params, auth_user=auth_user
        )

        # enroll another token for max1, now with issuer
        params = {
            "user": "max1",
            "realm": "myOtherRealm",
            "serial": "hmac3",
            "type": "hmac",
            "genkey": 1,
        }
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="init", params=params, auth_user=auth_user
        )

        msg = "otpauth://hotp/fakeissuer-myOtherRealm:max1?"
        enrollment_url = response.json["detail"]["enrollment_url"]["value"]
        googleurl = response.json["detail"]["googleurl"]["value"]
        assert msg in enrollment_url, response
        assert msg in googleurl, response

        # delete the tokens of the user
        for serial in ["hmac1", "hmac2", "hmac3"]:
            params = {"serial": serial}
            auth_user = "superadmin"
            response = self.make_admin_request(
                action="remove", params=params, auth_user=auth_user
            )

            assert response.json["result"]["status"], response

        # delete the policies
        params = {"name": "tokenlabel_per_user"}
        auth_user = "superadmin"
        response = self.make_system_request(
            action="delPolicy", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        params = {"name": "tokenissuer_with_realm"}
        auth_user = "superadmin"
        response = self.make_system_request(
            action="delPolicy", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

    @pytest.mark.usefixtures("realms_and_resolver", "admin_roles")
    def test_712_autoassignment_for_users(self):
        """
        Policy 712: Testing scope=enrollment, autoassignment for
                    different users

        Remark: added multiple tokens to the test case

        max1/password1
        max2/password2
        """

        tokens = {
            "token1": {
                "type": "hmac",
                "otpkey": "d9848218d9977592fa70522579ec00e30adc490a",
                "otpval": "585489",
            },
            "token2": {
                "type": "hmac",
                "otpkey": "6b9c172fd7a521e57891f758141ce66741694c59",
                "otpval": "843851",
            },
        }
        params = {
            "name": "autoassignment_user",
            "scope": "enrollment",
            "realm": "myOtherRealm",
            "user": "max1",
            "action": "autoassignment",
            "client": "",
        }
        auth_user = "superadmin"
        response = self.make_system_request(
            action="setPolicy", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        # generate dummy tokens from template token1
        token_template = tokens["token1"]

        for i in range(5):
            serial = f"token0{i}"
            descr = copy.deepcopy(token_template)
            descr["otpkey"] = f"{token_template['otpkey'][:-1]}{i}"
            tokens[serial] = descr

        for i in range(5):
            serial = f"token1{i}"
            descr = copy.deepcopy(token_template)
            descr["otpkey"] = f"{token_template['otpkey'][:-1]}{i}"
            tokens[serial] = descr

        # enroll tokens in realm myOtherRealm
        for serial, descr in list(tokens.items()):
            params = {
                "type": "hmac",
                "serial": serial,
                "otpkey": descr["otpkey"],
                "realm": "myOtherRealm",
            }
            auth_user = "superadmin"
            response = self.make_admin_request(
                action="init", params=params, auth_user=auth_user
            )

            assert response.json["result"]["value"], response

        for serial in tokens:
            # set realm of tokens
            params = {
                "serial": serial,
                "realms": "myOtherRealm",
            }
            auth_user = "superadmin"
            response = self.make_admin_request(
                action="tokenrealm", params=params, auth_user=auth_user
            )

            assert response.json["result"]["status"], response
            assert response.json["result"]["value"] == 1, response

            # check tokens in realm
            params = {"serial": serial}
            auth_user = "superadmin"
            response = self.make_admin_request(
                action="show", params=params, auth_user=auth_user
            )

            token_found = False
            show_tokens = response.json["result"]["value"]["data"]
            for token in show_tokens:
                if token["LinOtp.TokenSerialnumber"] == serial:
                    assert token["LinOtp.CountWindow"] == 10, token
                    assert token["LinOtp.MaxFail"] == 10, token
                    assert token["User.description"] == "", token
                    assert token["LinOtp.IdResClass"] == "", token
                    assert "myotherrealm" in token["LinOtp.RealmNames"], token
                    token_found = True

            assert token_found, tokens

        # authenticate max1, gets the token assigned.
        serial = "token1"
        descr = tokens[serial]
        params = {
            "user": "max1",
            "realm": "myotherrealm",
            "pass": "password{}".format(descr["otpval"]),
        }
        response = self.make_validate_request(action="check", params=params)

        assert response.json["result"]["value"], response

        # check tokens belongs to max
        params = {"serial": serial}
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="show", params=params, auth_user=auth_user
        )

        token_found = False
        show_tokens = response.json["result"]["value"]["data"]
        for token in show_tokens:
            if token["LinOtp.TokenSerialnumber"] == serial:
                assert token["LinOtp.CountWindow"] == 10, token
                assert token["LinOtp.MaxFail"] == 10, token
                assert token["User.username"] == "max1", token
                assert "myotherrealm" in token["LinOtp.RealmNames"], token
                token_found = True

        assert token_found, show_tokens

        serial = "token2"
        descr = tokens[serial]
        params = {
            "user": "max2",
            "realm": "myotherrealm",
            "pass": "password{}".format(descr["otpval"]),
        }

        # max 2 can not autoassign a token pw2
        response = self.make_validate_request(action="check", params=params)

        assert not response.json["result"]["value"], response

        # delete the tokens of the user
        for serial in list(tokens.keys()):
            params = {"serial": serial}
            auth_user = "superadmin"
            response = self.make_admin_request(
                action="remove", params=params, auth_user=auth_user
            )

            assert response.json["result"]["status"], response

        # delete the policy
        params = {"name": "autoassignment_user"}
        auth_user = "superadmin"
        response = self.make_system_request(
            action="delPolicy", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

    @pytest.mark.usefixtures("realms_and_resolver", "admin_roles")
    def test_712b_autoassignment_for_users(self):
        """
        Policy 712: Testing scope=enrollment, autoassignment(as true)
                    for different users

        Remark: added multiple tokens to the test case
                useing the autoassignment policy without value

        max1/password1
        max2/password2
        """

        tokens = {
            "token1": {
                "type": "hmac",
                "otpkey": "d9848218d9977592fa70522579ec00e30adc490a",
                "otpval": "585489",
            },
            "token2": {
                "type": "hmac",
                "otpkey": "6b9c172fd7a521e57891f758141ce66741694c59",
                "otpval": "843851",
            },
        }
        params = {
            "name": "autoassignment_user",
            "scope": "enrollment",
            "realm": "myOtherRealm",
            "user": "max1",
            "action": "autoassignment",
            "client": "",
        }
        auth_user = "superadmin"
        response = self.make_system_request(
            action="setPolicy", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        # generate dummy tokens from template token1
        token_template = tokens["token1"]

        for i in range(5):
            serial = f"token0{i}"
            descr = copy.deepcopy(token_template)
            descr["otpkey"] = f"{token_template['otpkey'][:-1]}{i}"
            tokens[serial] = descr

        for i in range(5):
            serial = f"token1{i}"
            descr = copy.deepcopy(token_template)
            descr["otpkey"] = f"{token_template['otpkey'][:-1]}{i}"
            tokens[serial] = descr

        # enroll tokens in realm myOtherRealm
        for serial, descr in tokens.items():
            params = {
                "type": "hmac",
                "serial": serial,
                "otpkey": descr["otpkey"],
                "realm": "myOtherRealm",
            }
            auth_user = "superadmin"
            response = self.make_admin_request(
                action="init", params=params, auth_user=auth_user
            )

            assert response.json["result"]["value"], response

        for serial in tokens:
            # set realm of tokens
            params = {
                "serial": serial,
                "realms": "myOtherRealm",
            }
            auth_user = "superadmin"
            response = self.make_admin_request(
                action="tokenrealm", params=params, auth_user=auth_user
            )

            assert response.json["result"]["status"], response
            assert response.json["result"]["value"] == 1, response

            # check tokens in realm
            params = {"serial": serial}
            auth_user = "superadmin"
            response = self.make_admin_request(
                action="show", params=params, auth_user=auth_user
            )

            token_found = False
            show_tokens = response.json["result"]["value"]["data"]
            for token in show_tokens:
                if token["LinOtp.TokenSerialnumber"] == serial:
                    assert token["LinOtp.CountWindow"] == 10, token
                    assert token["LinOtp.MaxFail"] == 10, token
                    assert token["LinOtp.IdResClass"] == "", token
                    assert "myotherrealm" in token["LinOtp.RealmNames"], token
                    token_found = True

            assert token_found, show_tokens

        # authenticate max1, gets the token assigned.
        serial = "token1"
        descr = tokens[serial]
        params = {
            "user": "max1",
            "realm": "myotherrealm",
            "pass": "password{}".format(descr["otpval"]),
        }
        response = self.make_validate_request(action="check", params=params)

        assert response.json["result"]["value"], response

        # check tokens belongs to max
        params = {"serial": serial}
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="show", params=params, auth_user=auth_user
        )

        token_found = False
        show_tokens = response.json["result"]["value"]["data"]
        for token in show_tokens:
            if token["LinOtp.TokenSerialnumber"] == serial:
                assert token["LinOtp.CountWindow"] == 10, token
                assert token["LinOtp.MaxFail"] == 10, token
                assert token["User.username"] == "max1", token
                assert "myotherrealm" in token["LinOtp.RealmNames"], token
                token_found = True

        assert token_found, show_tokens

        serial = "token2"
        descr = tokens[serial]
        params = {
            "user": "max2",
            "realm": "myotherrealm",
            "pass": "password{}".format(descr["otpval"]),
        }

        # max 2 can not autoassign a token pw2
        response = self.make_validate_request(action="check", params=params)

        assert not response.json["result"]["value"], response

        # delete the tokens of the user
        for serial in list(tokens.keys()):
            params = {"serial": serial}
            auth_user = "superadmin"
            response = self.make_admin_request(
                action="remove", params=params, auth_user=auth_user
            )

            assert response.json["result"]["status"], response

        # delete the policy
        params = {"name": "autoassignment_user"}
        auth_user = "superadmin"
        response = self.make_system_request(
            action="delPolicy", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

    @pytest.mark.usefixtures("realms_and_resolver", "admin_roles")
    def test_713_losttoken_for_users(self):
        """
        Policy 713: Testing scope=enrollment, losttoken for different users.

        max1 gets pwlen=10
        max2 gets pwlen=20
        """
        params = {
            "name": "losttoken_user_1",
            "scope": "enrollment",
            "realm": "myOtherRealm",
            "user": "max1",
            "action": "lostTokenPWLen=8",
            "client": "",
        }
        auth_user = "superadmin"
        response = self.make_system_request(
            action="setPolicy", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        params = {
            "name": "losttoken_user_2",
            "scope": "enrollment",
            "realm": "myOtherRealm",
            "user": "max2",
            "action": "lostTokenPWLen=20",
            "client": "",
        }
        auth_user = "superadmin"
        response = self.make_system_request(
            action="setPolicy", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

        # enroll tokens in realm myOtherRealm
        params = {
            "type": "hmac",  # OTP: 585489
            "user": "max1",
            "realm": "myOtherRealm",
            "serial": "token1",
            "otpkey": "d9848218d9977592fa70522579ec00e30adc490a",
        }
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="init", params=params, auth_user=auth_user
        )

        assert response.json["result"]["value"], response

        params = {
            "type": "hmac",  # OTP: 843851
            "serial": "token2",
            "user": "max2",
            "realm": "myOtherRealm",
            "otpkey": "6b9c172fd7a521e57891f758141ce66741694c59",
        }
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="init", params=params, auth_user=auth_user
        )

        assert response.json["result"]["value"], response

        # generate lost tokens
        params = {"serial": "token1"}
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="losttoken", params=params, auth_user=auth_user
        )

        # check for password length 10
        pw_len = re.search(r'"password": "\S{8}"', str(response))
        assert pw_len is not None, response

        params = {"serial": "token2"}
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="losttoken", params=params, auth_user=auth_user
        )

        # check for password length 10
        pw_len = re.search(r'"password": "\S{20}"', str(response))
        assert pw_len is not None, response

        # delete the tokens of the user
        for serial in ["token1", "token2", "losttoken1", "losttoken2"]:
            params = {"serial": serial}
            auth_user = "superadmin"
            response = self.make_admin_request(
                action="remove", params=params, auth_user=auth_user
            )

            assert response.json["result"]["status"], response

        # delete the policy
        for p in ["losttoken_user_1", "losttoken_user_2"]:
            params = {"name": p}
            auth_user = "superadmin"
            response = self.make_system_request(
                action="delPolicy", params=params, auth_user=auth_user
            )

            assert response.json["result"]["status"], response

    @pytest.mark.usefixtures("realms_and_resolver", "admin_roles", "enroll_tokens")
    def test_810_admin_is_not_allowed_to_show(self):
        """
        Policy 810: admin only wants to show tokens of a selected realm

        Although the admin is allowed to view tokens in two realms,
        he only wants to see the tokens of one realm.
        """
        policies = [
            {
                "name": "admin_show_1",
                "scope": "admin",
                "realm": "testrealm, myDefRealm",
                "action": "show",
                "user": "show_admin_1",
                "client": "",
            },
        ]
        # create policies
        for policy in policies:
            auth_user = "superadmin"
            response = self.make_system_request(
                action="setPolicy", params=policy, auth_user=auth_user
            )

            assert response.json["result"]["status"], response
            pkey = "setPolicy {}".format(policy.get("name"))
            values = set(response.json["result"]["value"][pkey].values())
            assert False not in values, response

        # test, if admin show_admin_1 is not allowed to show
        params = {"viewrealm": "testrealm"}
        auth_user = "show_admin_1"
        response = self.make_admin_request(
            action="show", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response

    @pytest.mark.usefixtures("realms_and_resolver", "admin_roles", "enroll_tokens")
    def test_812_empty_policy_name(self):
        """
        Policy 819: Saving policies with empty policy name is not possible
        """
        policy = {
            "name": "",
            "scope": "admin",
            "realm": "*",
            "action": "initETNG",
        }
        auth_user = "superadmin"
        response = self.make_system_request(
            action="setPolicy", params=policy, auth_user=auth_user
        )

        assert not response.json["result"]["status"], response
        msg = "The name of the policy must not be empty"
        assert response.json["result"]["error"]["message"] == msg, response

    @pytest.mark.usefixtures("realms_and_resolver", "admin_roles", "enroll_tokens")
    def test_820_detail_on_success(self):
        """
        Policy 820: check the authorization/detail_on_success and
                    detail_on_fail policy
        """
        # enroll token
        params = {
            "serial": "detail01",
            "type": "spass",
            "pin": "secret",
            "user": "detail_user",
            "realm": "myMixRealm",
        }
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="init", params=params, auth_user=auth_user
        )

        assert response.json["result"]["status"], response
        assert response.json["result"]["value"], response

        policies = [
            {
                "name": "detail_1",
                "scope": "authorization",
                "realm": "myMixRealm",
                "action": "detail_on_success",
                "user": "*",
                "client": "",
            },
            {
                "name": "detail_2",
                "scope": "authorization",
                "realm": "myMixRealm",
                "action": "detail_on_fail",
                "user": "*",
                "client": "",
            },
        ]

        # set policy for authorization
        for pol in policies:
            auth_user = "superadmin"
            response = self.make_system_request(
                action="setPolicy", params=pol, auth_user=auth_user
            )

            assert response.json["result"]["status"], response
            assert response.json["result"]["value"][
                "setPolicy {}".format(pol["name"])
            ], response

        # check the successful validation
        params = {"user": "detail_user@myMixRealm", "pass": "secret"}
        response = self.make_validate_request(action="check", params=params)

        assert response.json["result"]["value"], response
        assert response.json["detail"]["serial"] == "detail01", response
        assert response.json["detail"]["realm"] == "mymixrealm", response
        assert response.json["detail"]["is_linotp_admin"] is False, response
        assert response.json["detail"]["tokentype"] == "spass", response
        expected_user = {
            "username": "detail_user",
            "userid": "2101",
            "description": None,
            "email": None,
            "givenname": None,
            "surname": None,
            "phone": None,
            "mobile": None,
        }
        assert response.json["detail"]["user"] == expected_user, response

        # check failed validation
        params = {"user": "detail_user@myMixRealm", "pass": "wrong"}
        response = self.make_validate_request(action="check", params=params)

        assert not response.json["result"]["value"], response
        assert "wrong otp pin -1" in response.json["detail"]["error"], response

        # delete policies
        for pol in ["detail_1", "detail_2"]:
            params = {"name": pol}
            auth_user = "superadmin"
            response = self.make_system_request(
                action="delPolicy", params=params, auth_user=auth_user
            )

            assert response.json["result"]["status"], response
            assert response.json["result"]["value"]["delPolicy"]

        # delete token
        params = {"serial": "detail01"}
        auth_user = "superadmin"
        response = self.make_admin_request(
            action="remove", params=params, auth_user=auth_user
        )

        assert response.json["result"]["value"] == 1, response

    @pytest.mark.usefixtures("realms_and_resolver", "admin_roles")
    def test_detail_on_success_with_passing_policies_passthru(self):
        """
        Check the authorization/detail_on_success with
        passthru policy for users without tokens
        """
        self._test_detail_on_success_with_passing_policies("passthru")

    @pytest.mark.usefixtures("realms_and_resolver", "admin_roles")
    def test_detail_on_success_with_passing_policies_passOnNoToken(self):
        """
        Check the authorization/detail_on_success with
        passOnNoToken policy for users without tokens
        """
        self._test_detail_on_success_with_passing_policies("passOnNoToken")

    def _test_detail_on_success_with_passing_policies(self, auth_policy):
        """
        Helper method to test detail_on_success with different authentication policies
        """
        # Set policies for authorization and authentication
        policies = [
            {
                "name": "detail_on_success",
                "scope": "authorization",
                "realm": "myMixRealm",
                "action": "detail_on_success",
                "user": "*",
                "client": "",
            },
            {
                "name": auth_policy,
                "scope": "authentication",
                "realm": "myMixRealm",
                "action": auth_policy,
                "user": "*",
                "client": "",
            },
        ]

        # Create policies
        for pol in policies:
            response = self.make_system_request(
                action="setPolicy", params=pol, auth_user="superadmin"
            )
            assert response.json["result"]["status"], response
            assert response.json["result"]["value"][f"setPolicy {pol['name']}"], (
                response
            )

        # Check successful validation with detail_on_success
        params = {"user": "passthru_user1@myMixRealm", "pass": "geheim1"}
        response = self.make_validate_request(action="check", params=params)

        assert response.json["result"]["value"], response
        assert response.json["detail"]["realm"] == "myMixRealm", response
        assert response.json["detail"]["is_linotp_admin"] is False, response

        expected_user = {
            "username": "passthru_user1",
            "userid": "1100",
            "description": "Pascal True,Room 23,+49(0)1234-24,+49(0)5678-23,pass.true@example.com",
            "email": "pass.true@example.com",
            "givenname": "Pascal",
            "surname": "True",
            "phone": "+49(0)5678-23",
            "mobile": "+49(0)1234-24",
        }
        assert response.json["detail"]["user"] == expected_user, response

        # Clean up - delete policies
        for pol in policies:
            response = self.make_system_request(
                action="delPolicy",
                params={"name": pol["name"]},
                auth_user="superadmin",
            )
            assert response.json["result"]["status"], response
            assert response.json["result"]["value"]["delPolicy"]

    @pytest.mark.usefixtures("realms_and_resolver", "admin_roles")
    def test_setrealm_in_check_status(self):
        """
        Confirm that setrealm changes the realm in check_status
        LINOTP-2275
        """
        # Set policies for authorization and authentication
        real_realm = "myDefRealm"
        other_realm = "myMixRealm"

        policies = [
            {
                "name": "setrealm",
                "scope": "authorization",
                "realm": "*",
                "action": f"setrealm={real_realm}",
                "user": "*",
                "client": "",
            },
            {
                "name": "challenge_response",
                "scope": "authentication",
                "realm": "*",
                "action": "challenge_response=*",
                "user": "*",
                "client": "",
            },
        ]

        # Create policies
        for pol in policies:
            response = self.make_system_request(
                action="setPolicy", params=pol, auth_user="superadmin"
            )
            assert response.json["result"]["status"], response
            assert response.json["result"]["value"][f"setPolicy {pol['name']}"], (
                response
            )

        # enroll token
        user = "passthru_user1"
        otpkey = "otpkey"
        pin = "pin"

        params = {
            "user": user,
            "realm": real_realm,
            "type": "pw",
            "otpkey": otpkey,
            "pin": pin,
        }
        response = self.make_admin_request(
            action="init", params=params, auth_user="superadmin"
        )
        assert response.json["result"]["status"], response
        assert response.json["result"]["value"], response

        # make validate/check request with real_realm to trigger challenge
        response = self.make_validate_request(
            action="check",
            params={"user": user, "realm": real_realm, "pass": pin},
        )
        assert response.json["result"]["status"] is True, response
        assert response.json["result"]["value"] is False, response
        transaction_id = response.json["detail"]["transactionid"]
        assert transaction_id, response

        # check challenge status with other_realm
        response = self.make_validate_request(
            action="check_status",
            params={
                "user": user,
                "realm": other_realm,
                "transactionid": transaction_id,
                "pass": pin,
            },
        )
        assert response.json["result"]["status"] is True, response
        assert response.json["result"]["value"] is True, response
        assert response.json["detail"]["transactions"][transaction_id] is not None, (
            response
        )

        # Accept challenge with other_realm
        response = self.make_validate_request(
            action="check",
            params={
                "user": user,
                "realm": other_realm,
                "transactionid": transaction_id,
                "pass": otpkey,
            },
        )
        assert response.json["result"]["status"] is True, response
        assert response.json["result"]["value"] is True, response

        # Clean up - delete policies
        for pol in policies:
            response = self.make_system_request(
                action="delPolicy",
                params={"name": pol["name"]},
                auth_user="superadmin",
            )
            assert response.json["result"]["status"], response
            assert response.json["result"]["value"]["delPolicy"]
