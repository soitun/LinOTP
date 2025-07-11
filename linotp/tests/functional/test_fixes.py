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
Tests for some miscellaneous fixes
"""

import json
import threading

import pytest

from linotp.tests import TestController


@pytest.mark.exclude_sqlite
def test_ticket_425(app, adminclient):
    """
    Test #2425: test if setConfig is timing save

    1. run multiple setConfig threads concurrently
    2. verify that only one thread has written his config
    3. verify, that all config entries of this thread are in place

    config entries are of format: key_entryId = val_threadId
            eg. key_101 = val_4 belongs to thread 4 and is entry 101
    """

    class DoRequest(threading.Thread):
        """the request thread"""

        def __init__(self, app, rid=1, params=None):
            """
            initialize all settings of the request thread

            :param app: flask app
            :param rid: the request id
            :param uri: the request url object
            :param params: additional parmeters
            """
            threading.Thread.__init__(self)

            self.client = app.test_client()
            self.rid = rid
            self.params = params

            self.response = None

        def run(self):
            """start the thread"""
            response = self.client.post("/system/setConfig", json=self.params)
            self.response = response.json

        def status(self):
            """
            retrieve the request result

            :return: the thread request result
            """
            res = '"status": true,' in self.response
            return res

        def stat(self):
            """
            retrieve the complete response
            """
            return (self.rid, self.response)

    check_results = []
    numthreads = 20
    numkeys = 200

    # We need to make a first request to initialize
    # "linotp.SecretKey.Partition.0" before the threads are started.
    # If we do not do this here, than there is a race condition for
    # all threads trying to init the secretKey config row.
    adminclient.get("/system/getConfig")

    params = {}

    for tid in range(numthreads):
        param = {}
        for kid in range(numkeys):
            key = f"key_{kid}"
            val = f"val_{tid}"
            param[key] = val
        params[tid] = param

    for tid in range(numthreads):
        param = params.get(tid)
        current = DoRequest(app, rid=tid, params=param)
        check_results.append(current)
        current.start()

    # wait till all threads are completed
    for req in check_results:
        req.join()

    # now check in the config if all keys are there
    config_response = adminclient.get("/system/getConfig")
    conf = config_response.json["result"]["value"]

    # check for the keys and the values in the dict
    counter = 0
    valdict = set()

    for cconf in conf:
        if cconf.startswith("key_"):
            valdict.add(conf.get(cconf))
            counter += 1

    assert counter == numkeys
    assert len(valdict) == 1


class TestFixesController(TestController):
    """
    test some fixes for closed tickets
    """

    def setUp(self):
        """setup the Test Controller"""
        TestController.setUp(self)
        self.create_common_resolvers()
        self.create_common_realms()
        self.serials = []

    def tearDown(self):
        """make the dishes"""

        for kid in range(200):
            key = f"key_{kid}"
            self.make_system_request("delConfig", params={"key": key})

        self.remove_tokens()
        self.delete_all_realms()
        self.delete_all_resolvers()
        TestController.tearDown(self)

    def remove_tokens(self):
        """
        remove all tokens, which are in the internal array of serial

        :return: - nothing -
        """
        for serial in self.serials:
            self.del_token(serial)

    def del_token(self, serial):
        """
        delet a token identified by his serial number

        :param serial: the token serial
        :return: the response object of admin/remove
        """
        param = {"serial": serial}
        response = self.make_admin_request("remove", params=param)
        return response

    def get_config(self):
        """
        get the linotp config

        :return: the response object of the system/getConfig
        """
        param = {}
        response = self.make_system_request("getConfig", params=param)
        return response

    def add_token(
        self,
        user,
        pin=None,
        serial=None,
        typ=None,
        key=None,
        timeStep=60,
        timeShift=0,
        hashlib="sha1",
        otplen=8,
    ):
        """
        add a token to LinOTP

        :param user: user that owns the token
        :param pin: token pin - if none use the user name
        :param serial: give serial number
        :parm typ: token type
        :param key: the secret key
        :param timeStep: the TOTP time step
        :param timeShift: the TOTP time shift
        :param hashlib: the hmac hashlib
        :param otplen: the otp length

        :return: tuple of serial and response
        """
        if serial is None:
            serial = "s" + user

        if pin is None:
            pin = user

        if typ is None:
            typ = "totp"

        param = {
            "user": user,
            "pin": pin,
            "serial": serial,
            "type": typ,
            "timeStep": timeStep,
            "otplen": otplen,
            "hashlib": hashlib,
        }
        if timeShift != 0:
            param["timeShift"] = timeShift

        if key is not None:
            param["otpkey"] = key

        response = self.make_admin_request("init", params=param)
        assert '"status": true,' in response

        return (serial, response)

    def test_ticket_864(self):
        """
        #2864: admin/tokenrealm with multiple realms
        remarks:
            the problem is independent of sqlite, the reason is that realms are
            treated case insensitive
        1. create a token
        2. add some realms to the token
        3. verify, that the token is part of the realms
        """

        self.add_token("root", serial="troot", typ="spass", key="1234")

        param = {"serial": "troot", "realms": "myDefRealm,myMixRealm"}
        response = self.make_admin_request("tokenrealm", params=param)
        if '"value": 1' not in response.body:
            assert '"value": 1' in response.body

        param = {}
        # the admin show returns slices of 10 token and our troot is not in
        # the first slice :-( - so we now search directly for the token
        param["serial"] = "troot"
        response = self.make_admin_request("show", params=param)
        resp = json.loads(response.body)
        tok_data = resp.get("result").get("value").get("data")[0]
        realms = tok_data.get("LinOtp.RealmNames")
        t_ser = tok_data.get("LinOtp.TokenSerialnumber")

        assert t_ser == "troot"
        assert "mydefrealm" in realms
        assert "mymixrealm" in realms

        self.del_token("troot")

    def test_ticket_12018(self):
        """
        #12018: OTPLen of /admin/init is not ignored
        """
        (serial, response) = self.add_token(
            "root", serial="troot", typ="hmac", key="1234", otplen=8
        )
        assert serial == "troot", response

        param = {}
        response = self.make_admin_request("show", params=param)
        # resp = json.loads(response.body)
        assert '"LinOtp.OtpLen": 8' in response

        res = self.del_token(serial)
        assert '"status": true,' in res
        assert '"value": 1' in res


# eof###########################################################################
