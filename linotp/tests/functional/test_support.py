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
Testing the set license
"""

import json
import logging
import os
from datetime import datetime, timedelta
from unittest.mock import patch

from freezegun import freeze_time

import linotp.lib.support
from linotp.lib.support import InvalidLicenseException
from linotp.tests import TestController

log = logging.getLogger(__name__)


class TestSupport(TestController):
    def setUp(self):
        self.delete_license()
        self.delete_all_token()

        self.create_common_resolvers()
        self.create_common_realms()

        return TestController.setUp(self)

    def tearDown(self):
        self.delete_license()
        self.delete_all_token()

        self.delete_all_realms()
        self.delete_all_resolvers()

        # remove the license, if installed

        self.make_system_request("delConfig", params={"key": "license"})

        return TestController.tearDown(self)

    def install_license(self, license_filename="demo-lic.pem"):
        """
        install a license from the fixture path
        """

        demo_license_file = os.path.join(self.fixture_path, license_filename)

        with open(demo_license_file) as f:
            demo_license = f.read()

        upload_files = [("license", "demo-lic.pem", demo_license)]

        response = self.make_system_request("setSupport", upload_files=upload_files)

        return response

    def check_appliance_demo_licence(self):
        """
        helper test which is called mocked or unmocked
        """

        # ------------------------------------------------------------------ --

        # check that there is no license installed

        params = {"key": "license"}
        response = self.make_system_request("getConfig", params)
        assert '"getConfig license": null' in response

        response = self.make_system_request("isSupportValid")

        if "your product is unlicensed" in response:
            msg = "your product is unlicensed"
            raise InvalidLicenseException(msg)

        assert '"status": true' in response
        assert '"value": true' in response

        # ------------------------------------------------------------------ --

        # now check that the demo license with expiry in +14 day is installed

        response = self.make_system_request("getSupportInfo")
        jresp = json.loads(response.body)
        expiry = jresp.get("result", {}).get("value", {}).get("expire")

        expiry_date = datetime.strptime(expiry, "%Y-%m-%d")
        expected_expiry = datetime.now() + timedelta(days=14)

        assert expiry_date.year == expected_expiry.year
        assert expiry_date.month == expected_expiry.month
        assert expiry_date.day == expected_expiry.day

    def test_demo_license_expiration(self):
        """
        text that the demo license expires after 14 days
        """
        two_weeks_ago = datetime.now() - timedelta(days=15)

        with freeze_time(two_weeks_ago):
            response = self.install_license(license_filename="demo-lic.pem")
            assert '"status": true' in response
            assert '"value": true' in response

        response = self.make_system_request("getSupportInfo")
        jresp = json.loads(response.body)
        expiry = jresp.get("result", {}).get("value", {}).get("expire")
        expiry_date = datetime.strptime(expiry, "%Y-%m-%d")

        # check that the license expiration date is before today
        assert expiry_date < datetime.now()

        response = self.make_system_request("isSupportValid")
        jresp = json.loads(response.body)

        assert not jresp.get("result", {}).get("value")
        assert "License expired" in jresp.get("detail", {}).get("reason")

    def test_set_expires_license(self):
        """
        check that installation of expired license fails
        """

        response = self.install_license(license_filename="expired-lic.pem")

        assert '"status": false' in response
        assert "expired - valid till '2017-12-12'" in response

    def test_set_license_fails(self):
        """
        check that license could not be installed if too many tokens are used
        """

        for i in range(1, 10):
            params = {"type": "hmac", "genkey": 1, "serial": f"HMAC_DEMO{i}"}
            response = self.make_admin_request("init", params)
            assert '"status": true' in response
            assert '"value": true' in response

        response = self.install_license(license_filename="demo-lic.pem")

        assert '"status": false' in response, response
        msg = "volume exceeded: 9 active tokens found > 5 tokens licensed."
        assert msg in response, response

    def test_appliance_demo_licence(self):
        """
        verify that if we are running on a sva2, the demo license is installed
        """

        # ------------------------------------------------------------------ --

        # first determin if the module support provides the function
        # running_on_appliance

        requires_patch = False
        if "running_on_appliance" in dir(linotp.lib.support):
            requires_patch = True

        # ------------------------------------------------------------------ --

        # depending on the existance of the function we must patch it or not

        if not requires_patch:
            return self.check_appliance_demo_licence()

        with patch(
            "linotp.controllers.system.running_on_appliance"
        ) as mocked_running_on_appliance:
            mocked_running_on_appliance.return_value = True
            return self.check_appliance_demo_licence()

    def test_license_restrictions(self):
        """
        if license is installed, no more than 5 tokens could be enrolled

        using the expired license with the expirtion date 2017-12-12
        """

        time_ago = datetime(year=2017, month=12, day=1)

        with freeze_time(time_ago):
            response = self.install_license(license_filename="expired-lic.pem")
            assert '"status": true' in response
            assert '"value": true' in response

            for i in range(1, 6 + 2):
                params = {
                    "type": "hmac",
                    "genkey": 1,
                    "serial": f"HMAC_DEMO{i}",
                }
                response = self.make_admin_request("init", params)
                assert '"status": true' in response
                assert '"value": true' in response

            params["serial"] = "HMAC_DEMO-XXX"
            response = self.make_admin_request("init", params)
            assert '"status": false' in response, response
            msg = "No more tokens can be enrolled due to license restrictions"
            assert msg in response, response

    def test_userservice_license_restrictions(self):
        """
        if license is installed, only a limited number of tokens could be enrolled via
        via the userservice api

         - an expired license with the expiration date 2017-12-12 is used
        """

        # ----------------------------------------------------------------- --

        # 0. setup the selfservice policies to allow token enrollment

        params = {
            "name": "enrollment_limit_test",
            "scope": "selfservice",
            "action": "enrollHMAC",
            "user": "*",
            "realm": "*",
            "active": True,
        }

        response = self.make_system_request("setPolicy", params)
        assert "false" not in response, response

        auth_user = {
            "login": "passthru_user1@myDefRealm",
            "password": "geheim1",
        }

        time_ago = datetime(year=2017, month=12, day=1)

        with freeze_time(time_ago):
            # ------------------------------------------------------------ --

            # 1. install the license with

            response = self.install_license(license_filename="expired-lic.pem")
            assert response.json["result"]["status"]
            assert response.json["result"]["value"]

            # ----------------------------------------------------------------- --

            # 2. enroll tokens up to the license limit, which is
            #    6 tokens + 2 grace tokens

            for _i in range(1, 6 + 2):
                response = self.make_userselfservice_request(
                    "enroll", params={"type": "hmac"}, auth_user=auth_user
                )

                assert response.json["result"]["status"]
                assert response.json["result"]["value"]

            # ------------------------------------------------------------- --

            # 3a. verify that userservice/enroll does not work

            response = self.make_userselfservice_request(
                "enroll", params={"type": "hmac"}, auth_user=auth_user
            )
            assert not response.json["result"]["status"]

            msg = "Failed to enroll token, please contact your administrator"
            assert msg in response.json["result"]["error"]["message"], response

    def test_token_user_license(self):
        """
        verify that the token user license check is working

        - the number of tokens is not limited, only the number of users
        - the number of tokens per user can be limited by the maxtoken policy
        - the number of tokens per realm can be limited by the tokencount policy
        """

        license_valid_date = datetime(year=2018, month=11, day=16)

        with freeze_time(license_valid_date):
            license_file = os.path.join(self.fixture_path, "linotp2.token_user.pem")
            with open(license_file) as f:
                license = f.read()

            upload_files = [("license", "linotp2.token_user.pem", license)]
            response = self.make_system_request("setSupport", upload_files=upload_files)
            assert '"status": true' in response
            assert '"value": true' in response

            response = self.make_system_request("getSupportInfo")
            jresp = json.loads(response.body)
            user_num = jresp.get("result", {}).get("value", {}).get("user-num")

            assert user_num == "4"

            # ------------------------------------------------------------- --

            # enrollment of two tokens per user
            # + 2 additional one for beeing nice to the customers :)
            # - tokens per user are not limited

            for user in ["hans", "rollo", "susi", "horst", "user1", "user2"]:
                for i in range(2):
                    params = {
                        "type": "pw",
                        "user": user + "@myDefRealm",
                        "otpkey": "geheim",
                        "serial": f"{user}.{i}",
                    }
                    response = self.make_admin_request("init", params)
                    assert '"value": true' in response, response

            response = self.make_system_request("isSupportValid")
            assert '"value": true' in response, response

            # ------------------------------------------------------------- --

            # enrollment to one more owner is not allowed

            params = {
                "type": "pw",
                "user": "root@myDefRealm",
                "otpkey": "geheim",
            }

            response = self.make_admin_request("init", params)
            assert '"status": false' in response
            msg = "No more tokens can be enrolled due to license restrictions"
            assert msg in response

            # ------------------------------------------------------------- --

            # disable one of the users tokens and now we can enroll more users

            for i in range(2):
                params = {
                    "serial": f"hans.{i}",
                }
                response = self.make_admin_request("disable", params)
                assert '"value": 1' in response

            for i in range(2):
                params = {
                    "type": "pw",
                    "user": "root@myDefRealm",
                    "otpkey": "geheim",
                    "serial": f"root.{i}",
                }

                response = self.make_admin_request("init", params)
                assert '"value": true' in response

            # ------------------------------------------------------------- --

            # enable check - would create one more active token user, which
            # is not allowed

            params = {
                "serial": "hans.1",
            }

            response = self.make_admin_request("enable", params)
            assert '"status": false' in response
            msg = "No more tokens can be enrolled due to license restrictions"
            assert msg in response

            # ------------------------------------------------------------- --

            # assignment check - would create one more active token user,
            # which is not allowed

            params = {
                "serial": "root.1",
                "user": "hans@myDefRealm",
            }

            response = self.make_admin_request("assign", params)
            assert '"status": false' in response
            msg = "No more tokens can be enrolled due to license restrictions"
            assert msg in response

            # ------------------------------------------------------------- --

            # maxtoken - limit the tokens per user

            params = {
                "name": "max_token_per_user",
                "action": "maxtoken=3",
                "active": True,
                "scope": "enrollment",
                "realm": "*",
                "user": "*",
                "client": "*",
            }

            response = self.make_system_request("setPolicy", params)
            assert response.json["result"]["status"]

            # a 3rd token is allowed

            user = "user2"
            params = {
                "type": "pw",
                "user": user + "@myDefRealm",
                "otpkey": "geheim",
                "serial": f"{user}.{3}",
            }
            response = self.make_admin_request("init", params)
            assert response.json["result"]["value"], response

            # but no further token is allowed

            params = {
                "type": "pw",
                "user": user + "@myDefRealm",
                "otpkey": "geheim",
                "serial": f"{user}.{4}",
            }
            response = self.make_admin_request("init", params)
            assert not response.json["result"]["status"], response
            assert response.json["result"]["error"]["code"] == 411, response

            # ------------------------------------------------------------- --

            # tokencount - limit the tokens per realm

            params = {
                "name": "max_token_per_user",
                "action": "tokencount=14",
                "active": True,
                "scope": "enrollment",
                "realm": "mydefrealm",
                "user": "*",
                "client": "*",
            }

            response = self.make_system_request("setPolicy", params)
            assert response.json["result"]["status"]

            user = "user1"

            params = {
                "type": "pw",
                "user": user + "@myDefRealm",
                "otpkey": "geheim",
                "serial": f"{user}.{3}",
            }
            response = self.make_admin_request("init", params)
            assert response.json["result"]["value"], response

            user = "horst"

            params = {
                "type": "pw",
                "user": user + "@myDefRealm",
                "otpkey": "geheim",
                "serial": f"{user}.{3}",
            }
            response = self.make_admin_request("init", params)
            assert not response.json["result"]["status"], response
            assert response.json["result"]["error"]["code"] == 410, response
            msg = (
                "The maximum allowed number of tokens for the realm "
                "'myDefRealm' was reached. You can not init any more tokens"
            )

            assert msg in response.json["result"]["error"]["message"], response

    def test_tokencount_user_license(self):
        """
        verify that the token user license check is working
        """

        params = {
            "name": "token_count_limit",
            "scope": "enrollment",
            "realm": "mydefrealm",
            "user": "*",
            "active": True,
            "action": "tokencount=6",
        }

        response = self.make_system_request("setPolicy", params=params)
        assert "false" not in response.body

        license_valid_date = datetime(year=2018, month=11, day=16)

        with freeze_time(license_valid_date):
            license_file = os.path.join(self.fixture_path, "linotp2.token_user.pem")
            with open(license_file) as f:
                license = f.read()

            upload_files = [("license", "linotp2.token_user.pem", license)]
            response = self.make_system_request("setSupport", upload_files=upload_files)
            assert '"status": true' in response
            assert '"value": true' in response

            response = self.make_system_request("getSupportInfo")
            jresp = json.loads(response.body)
            user_num = jresp.get("result", {}).get("value", {}).get("user-num")

            assert user_num == "4"

            for user in ["hans", "rollo", "susi", "horst", "user1", "user2"]:
                params = {
                    "type": "pw",
                    "user": user + "@myDefRealm",
                    "otpkey": "geheim",
                }

                response = self.make_admin_request("init", params)
                assert '"value": true' in response

            response = self.make_system_request("isSupportValid")
            assert '"value": true' in response

            params = {
                "type": "pw",
                "user": "root@myDefRealm",
                "otpkey": "geheim",
            }

            response = self.make_admin_request("init", params)

            msg = "The maximum allowed number of tokens for the realm"
            assert msg in response

            response = self.make_system_request("isSupportValid")
            assert '"value": true' in response, response

    def test_forwardtoken_count_user_license(self):
        """
        verify that the forward token is not counted into the user license

        Note:
        exceeding calculation:

        license: 4 + grace limit: 2 = 6 allowed users
        the license exceeds with the 7th user

        """

        license_valid_date = datetime(year=2018, month=11, day=16)

        with freeze_time(license_valid_date):
            license_file = os.path.join(self.fixture_path, "linotp2.token_user.pem")
            with open(license_file) as f:
                license = f.read()

            upload_files = [("license", "linotp2.token_user.pem", license)]
            response = self.make_system_request("setSupport", upload_files=upload_files)
            assert '"status": true' in response
            assert '"value": true' in response

            response = self.make_system_request("getSupportInfo")
            jresp = json.loads(response.body)
            user_num = jresp.get("result", {}).get("value", {}).get("user-num")

            assert user_num == "4"

            # we currently have a grace Limit of 2 + a license of 4 = 6
            # so we enroll the maximum number of users
            for user in ["hans", "rollo", "susi", "horst", "user1", "user2"]:
                params = {
                    "type": "pw",
                    "user": user + "@myDefRealm",
                    "otpkey": "geheim",
                    "serial": "pw" + user,
                }

                response = self.make_admin_request("init", params)
                assert '"value": true' in response

            response = self.make_system_request("isSupportValid")
            assert '"value": true' in response

            # now we verify that no new user can have a token
            params = {
                "type": "pw",
                "user": "root@myDefRealm",
                "otpkey": "geheim",
            }

            response = self.make_admin_request("init", params)

            msg = "No more tokens can be enrolled due to license restrictions"
            assert msg in response, response

            # but a forward token is allowed
            params = {
                "type": "forward",
                "user": "root@myDefRealm",
                "otpkey": "geheim",
                "forward.serial": "pwhans",
            }

            response = self.make_admin_request("init", params)
            assert '"value": true' in response, response

            response = self.make_system_request("isSupportValid")
            assert '"value": true' in response, response

    def test_forwardtoken_count_token_license(self):
        """
        verify that the forward token is not counted into the user license

        Note:
        exceeding calculation:

        license: 4 + grace limit: 2 = 6 allowed users
        the license exceeds with the 7th user

        """

        licensed_tokens = 5
        grace_limit = 2

        time_ago = datetime(year=2017, month=12, day=1)

        with freeze_time(time_ago):
            response = self.install_license(license_filename="expired-lic.pem")
            assert '"status": true' in response
            assert '"value": true' in response

            for i in range(licensed_tokens + grace_limit):
                params = {
                    "type": "hmac",
                    "genkey": 1,
                    "serial": f"HMAC_DEMO{i}",
                }
                response = self.make_admin_request("init", params)
                assert '"status": true' in response
                assert '"value": true' in response

            response = self.make_system_request("getSupportInfo")
            jresp = json.loads(response.body)
            token_num = jresp.get("result", {}).get("value", {}).get("token-num")

            assert token_num == "5"

            # now we verify that no new token can be enrolled
            params = {
                "type": "hmac",
                "genkey": 1,
                "serial": "HMAC_DEMO100",
            }

            response = self.make_admin_request("init", params)

            msg = "No more tokens can be enrolled due to license restrictions"
            assert msg in response, response

            # but to enroll a forward token is allowed
            params = {
                "type": "forward",
                "otpkey": "geheim",
                "forward.serial": "HMAC_DEMO1",
            }

            response = self.make_admin_request("init", params)
            assert '"value": true' in response, response


# eof ########################################################################
