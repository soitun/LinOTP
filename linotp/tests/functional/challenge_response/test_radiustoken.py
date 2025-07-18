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
Test challenge response functionality for the radius token
"""

import contextlib
import logging
from unittest.mock import patch

# we need this for the radius token
from pyrad.client import Client
from pyrad.packet import AccessAccept, AccessChallenge, AccessReject

from . import TestChallengeResponseController

log = logging.getLogger(__name__)


RADIUS_RESPONSE_FUNC = None


class RadiusResponse:
    def __init__(self, auth, reply=None):
        if auth is True:
            self.code = AccessAccept
        elif auth is False:
            self.code = AccessReject
        else:
            self.code = AccessChallenge

        if not reply:
            self.reply = {}
        else:
            self.reply = reply

    # response[attr]
    def __getitem__(self, key):
        return self.reply.get(key)

    def keys(self):
        return list(self.reply.keys())


def mocked_radius_SendPacket(Client, *argparams, **kwparams):
    auth = True
    reply = None

    global RADIUS_RESPONSE_FUNC
    if RADIUS_RESPONSE_FUNC:
        test_func = RADIUS_RESPONSE_FUNC
        pkt = argparams[0]

        params = {}
        # contents of User-Name
        params["username"] = pkt[1][0]
        # encrypted User-Password
        params["password"] = pkt.PwDecrypt(pkt[2][0])

        with contextlib.suppress(Exception):
            params["state"] = pkt["State"][0]

        if test_func:
            auth, reply = test_func(params)

    response = RadiusResponse(auth, reply)

    return response


class TestRadiusTokenChallengeController(TestChallengeResponseController):
    def setUp(self):
        """
        This sets up all the resolvers and realms
        """
        TestChallengeResponseController.setUp(self)
        self.create_common_resolvers()
        self.create_common_realms()

        if hasattr(self, "policies") is False:
            self.policies = []

        if hasattr(self, "serials") is False:
            self.serials = []

        self.patch_smtp = None
        self.patch_sms = None

        self.delete_all_token()
        self.delete_all_policies()

        self.radius_url = f"localhost:{self.radius_authport}"

    def tearDown(self):
        self.delete_all_token()
        self.delete_all_realms()
        self.delete_all_resolvers()
        TestChallengeResponseController.tearDown(self)

    def setPinPolicy(
        self,
        name="otpPin",
        realm="ldap_realm",
        action="otppin=1, ",
        scope="authentication",
        active=True,
    ):
        params = {
            "name": name,
            "user": "*",
            "action": action,
            "scope": scope,
            "realm": realm,
            "time": "",
            "client": "",
            "active": active,
            "session": self.session,
        }
        _cookies = {"admin_session": self.session}

        response = self.make_system_request("setPolicy", params=params)
        assert response.json["result"]["status"], response

        response = self.make_system_request("getPolicy", params=params)
        assert response.json["result"]["status"], response

        self.policies.append(name)
        return response

    def setup_radius_token(self):
        serials = []

        # The token with the remote PIN
        params_list = [
            {
                "serial": "radius1",
                "type": "radius",
                "otpkey": "1234567890123456",
                "otppin": "",
                "user": "remoteuser",
                "pin": "",
                "description": "RadiusToken1",
                "radius.server": self.radius_url,
                "radius.local_checkpin": 0,
                "radius.user": "challenge",
                "radius.secret": "testing123",
                "session": self.session,
            },
            # the token with the local PIN
            {
                "serial": "radius2",
                "type": "radius",
                "otpkey": "1234567890123456",
                "otppin": "local",
                "user": "localuser",
                "pin": "local",
                "description": "RadiusToken2",
                "radius.server": self.radius_url,
                "radius.local_checkpin": 1,
                "radius.user": "user_no_pin",
                "radius.secret": "testing123",
                "session": self.session,
            },
        ]
        for params in params_list:
            response = self.make_admin_request(action="init", params=params)
            assert response.json["result"]["value"], response
            serials.append(params.get("serial"))

        return serials

    @patch.object(Client, "SendPacket", mocked_radius_SendPacket)
    def test_radiustoken_remote_pin(self):
        """
        Challenge Response Test: radius token with remote PIN
        """
        global RADIUS_RESPONSE_FUNC
        serials = self.setup_radius_token()
        user = "remoteuser"
        otp = "test123456"

        # now switch policy on for challenge_response for hmac token
        response = self.setPinPolicy(
            name="ch_resp", realm="*", action="challenge_response=radius"
        )
        assert response.json["result"]["status"], response

        # define validation function
        def check_func1(params):
            resp = False
            opt = None

            # check if we are in a chellenge request
            if params.get("password") == "test":
                opt = {}
                opt["State"] = ["012345678901"]
                opt["Reply-Message"] = ["text"]
                resp = opt

            return resp, opt

        # establish this in the global context as validation hook
        RADIUS_RESPONSE_FUNC = check_func1

        # 1.1 now trigger a challenge
        params = {"user": user, "pass": "test"}
        response = self.make_validate_request("check", params=params)

        assert not response.json["result"]["value"], response
        assert "transactionid" in response.json["detail"], response
        state = response.json["detail"]["transactionid"]

        # 1.2 check the challenge

        # define validation function
        def check_func2(params):
            resp = False
            opt = None

            # check if we are in a challenge request
            if (
                params.get("password") == "test123456"
                and params.get("state") == b"012345678901"
            ):
                resp = True

            return resp, opt

        # establish this in the global context as validation hook
        RADIUS_RESPONSE_FUNC = check_func2

        params = {"user": user, "pass": otp, "state": state}
        response = self.make_validate_request("check", params=params)

        # hey, if this ok, we are done for the remote pin check
        assert response.json["result"]["value"], response

        for serial in serials:
            self.delete_token(serial)

    @patch.object(Client, "SendPacket", mocked_radius_SendPacket)
    def test_radiustoken_local_pin(self):
        """
        Challenge Response Test: radius token with local PIN
        """
        global RADIUS_RESPONSE_FUNC

        serials = self.setup_radius_token()

        user = "localuser"
        otp = "654321"

        # now switch policy on for challenge_response for hmac token
        response = self.setPinPolicy(
            name="ch_resp", realm="*", action="challenge_response=radius"
        )
        assert response.json["result"]["value"], response

        # 1.1 now trigger a challenge
        # define validation function
        def check_func1(params):
            resp = False
            opt = None

            # check if we are in a chellenge request
            if params.get("password") == "test":
                opt = {}
                opt["State"] = ["012345678901"]
                opt["Reply-Message"] = ["text"]
                resp = opt

            return resp, opt

        # establish this in the global context as validation hook
        RADIUS_RESPONSE_FUNC = check_func1

        params = {"user": user, "pass": "local"}
        response = self.make_validate_request("check", params=params)
        assert not response.json["result"]["value"], response
        assert "transactionid" in response.json["detail"], response
        state = response.json["detail"]["transactionid"]

        # 1.2 check the challenge
        def check_func2(params):
            resp = False
            opt = None

            # check if we got the correct otp
            if params.get("password") == otp:
                resp = True

            return resp, opt

        # establish this in the global context as validation hook
        RADIUS_RESPONSE_FUNC = check_func2

        params = {"user": user, "pass": otp, "state": state}
        response = self.make_validate_request("check", params=params)

        # hey, if this ok, we are done for the remote pin check
        assert response.json["result"]["value"], response

        for serial in serials:
            self.delete_token(serial)


##eof##########################################################################
