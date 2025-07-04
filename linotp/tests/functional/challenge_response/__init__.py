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
Test challenge response functionality

These tests will only pass if you start a LinOTP server on 127.0.0.1.
For example with paster:

    paster serve test.ini

We assume port 5001 is used (default). If you want to use another port you can
specify it with nose-testconfig (e.g. --tc=paster.port:5005).
"""

import binascii
import json
import logging
import re
import time
import urllib.parse

from linotp.lib.HMAC import HmacOtp
from linotp.tests.functional.challenge_response.testing_controller import (
    TestingChallengeResponseController,
)

log = logging.getLogger(__name__)


def email_otp_func(call_args):
    """
    callback to extract the otp value from the mock interface parameters

    :param call_args: arguments to the smtp.SMTP.sendmail method
    :return: the extracted otp value as string
    """
    otp = None
    try:
        ordered_args = call_args[0]
        _email_from = ordered_args[0]
        _email_to = ordered_args[1]
        message = ordered_args[2]
        matches = re.search(r"\d{6}", message)
        otp = matches.group(0)
    except Exception as exx:
        log.error("email_otp failed: %r", exx)
    return otp


def sms_otp_func(call_args):
    """
    callback to extract the otp value from the mock interface parameters

    :param call_args: arguments to the smtp.SMTP.sendmail method
    :return: the extracted otp value as string
    """
    otp = None
    try:
        ordered_args = call_args[0]
        _phone = ordered_args[0]
        otp = ordered_args[1]
    except Exception as exx:
        log.error("sms_otp failed: %r", exx)
    return otp


def get_otp(counter=0, otpkey=None, mock_obj=None, otp_func=None, typ="hmac"):
    """
    extract from the context the otp value
    - if we have a mock_obj and a extractor callback, we are using this one
    - else we take the given otp value and the secret to calculate the new one

    :param counter: counter base for the otp calculation
    :param otpkey: the otpkey secret
    :param mock_obj: the mock hooked function which recieved the parameters
    :param otp_func: the otp extractor function
    """
    otp = None
    if mock_obj is not None:
        call_args = mock_obj.call_args
        # compare type of otp_func with known function
        if otp_func is not None and isinstance(otp_func, type(get_otp)):
            otp = otp_func(call_args)

    if otp is None:
        counter = counter + 1
        otp = calcOTP(otpkey, counter=counter, typ=typ)

    return otp


def calcOTP(key, counter=0, digits=6, typ=None):
    """
    as we have to use this method in a not class related function
    this function is extracted

    :param key: the otpkey secret
    :param counter: the related counter
    :param digits: the number of to be returned digits

    :return: the otp value as string
    """
    htoken = HmacOtp(digits=digits)
    if typ == "totp":
        log.debug("waiting for next time slot")
        timestep = 30
        time.sleep(timestep + 1)
        counter = int((time.time() / timestep) + 0.5)

    otp = htoken.generate(counter=counter, key=binascii.unhexlify(key))

    return otp


HTTP_RESPONSE_FUNC = None


def mocked_http_request(HttpObject, *argparams, **kwparams):
    resp = 200

    content = {
        "version": "LinOTP MOCK",
        "jsonrpc": "2.0",
        "result": {"status": True, "value": True},
        "id": 0,
    }
    status, response = TestChallengeResponseController.HTTP_RESPONSE
    if response:
        content = response
        resp = status

    global HTTP_RESPONSE_FUNC
    test_func = HTTP_RESPONSE_FUNC
    if test_func:
        body = kwparams.get("body")
        params = dict(urllib.parse.parse_qsl(body))
        resp, content = test_func(params)
        HTTP_RESPONSE_FUNC = None

    return resp, json.dumps(content)


class TestChallengeResponseController(TestingChallengeResponseController):
    radius_proc = None
    HTTP_RESPONSE = {}

    @classmethod
    def setup_class(cls):
        cls.radius_proc = cls.start_radius_server(
            cls.radius_authport, cls.radius_acctport
        )
        TestingChallengeResponseController.setup_class()

    @classmethod
    def teardown_class(cls):
        if cls.radius_proc:
            cls.stop_radius_server(cls.radius_proc)
        TestingChallengeResponseController.teardown_class()

    def setUp(self):
        """
        This sets up all the resolvers and realms
        """
        TestingChallengeResponseController.setUp(self)
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

        self.remote_url = f"http://127.0.0.1:{self.paster_port}"
        self.sms_url = f"http://localhost:{self.paster_port}/testing/http2sms"
        self.radius_url = (f"localhost:{self.radius_authport}",)

    def tearDown(self):
        if self.patch_smtp is not None:
            self.patch_smtp.stop()
        if self.patch_sms is not None:
            self.patch_sms.stop()

        self.delete_all_token()
        self.delete_all_realms()
        self.delete_all_resolvers()
        TestingChallengeResponseController.tearDown(self)

    def calcOTP(self, key, counter=0, digits=6, typ="hmac"):
        otp = calcOTP(key, counter=counter, digits=digits, typ=typ)
        return otp

    def createToken(
        self,
        serial="F722362",
        user="root",
        pin="pin",
        description="TestToken1",
        typ="hmac",
        otpkey="AD8EABE235FC57C815B26CEF3709075580B44738",
        phone=None,
        email_address=None,
        realm=None,
    ):
        params = {
            "serial": serial,
            "otpkey": otpkey,
            "user": user,
            "pin": pin,
            "type": typ,
            "description": description,
            "session": self.session,
        }
        if realm:
            params["realm"] = realm
        if phone is not None:
            params["phone"] = phone
        if email_address is not None:
            params["email_address"] = email_address

        response = self.make_admin_request(action="init", params=params)
        assert '"value": true' in response, response
        self.serials.append(serial)
        return serial

    def setPinPolicy(
        self,
        name="otpPin",
        realm="ldap_realm",
        action="otppin=1, ",
        scope="authentication",
        active=True,
        remoteurl=None,
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

        response = self.make_system_request("setPolicy", params=params)
        assert '"status": true' in response, response

        response = self.make_system_request("getPolicy", params=params)
        assert '"status": true' in response, response

        self.policies.append(name)
        return response

    def delete_remote_policy(self, name, url):
        """
        Delete policy on remote LinOTP found at url
        """
        params = {
            "name": name,
            "session": self.session,
        }
        cookies = {"admin_session": self.session}

        r_url = "{}/{}".format(url, "system/delPolicy")
        response = self.do_http_request(r_url, params=params, cookies=cookies)
        return response


##eof##########################################################################
