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
Verify LinOTP allows single-character resolver names, exercised through the
classic (non-v2) APIs: system/setResolver, system/getResolvers,
system/setRealm, admin/userlist, admin/init and validate/check.
"""

import os

from linotp.tests import TestController


class TestShortResolverName(TestController):
    """single-char resolver names."""

    def setUp(self):
        TestController.setUp(self)
        self.create_common_resolvers()
        self.create_common_realms()

    def tearDown(self):
        self.delete_all_policies()
        self.delete_all_token()
        self.delete_all_realms()
        self.delete_all_resolvers()
        TestController.tearDown(self)

    def _userlist_count(self, realm):
        response = self.make_admin_request("userlist", params={"realm": realm})
        assert response.json["result"]["status"], response
        return len(response.json["result"]["value"])

    def test_single_char_resolver(self):
        """a single-character resolver name works end-to-end.

        The backend imposes no minimum resolver-name length beyond one
        character (``linotp.lib.resolver.resolver_name_pattern`` ==
        ``^[a-zA-Z0-9_-]+$``). A one-character resolver can be created, is
        listed by system/getResolvers, can be bound to a single-char realm,
        resolves its users and authenticates a token.
        """
        passwd_file = os.path.join(self.fixture_path, "def-passwd")

        # create a passwd resolver with a one-character name
        response = self.create_resolver(
            name="r",
            params={
                "name": "r",
                "fileName": passwd_file,
                "type": "passwdresolver",
            },
        )
        assert response.json["result"]["value"], response

        # system/getResolvers lists the single-char resolver by name
        response = self.make_system_request("getResolvers")
        assert "r" in response.json["result"]["value"], response

        # bind the single-char resolver to a single-char realm
        response = self.create_realm(
            realm="z",
            resolvers="useridresolver.PasswdIdResolver.IdResolver.r",
        )
        assert response.json["result"]["value"], response

        # users resolve through the single-char resolver
        assert self._userlist_count("z") == 27

        # a token enrolled via the single-char resolver/realm authenticates
        params = {
            "serial": "PW-single-char-resolver",
            "type": "pw",
            "otpkey": "123456",
            "otppin": "geheim1",
            "pin": "geheim1",
            "user": "passthru_user1@z",
        }
        response = self.make_admin_request("init", params=params)
        assert response.json["result"]["value"], response

        response = self.make_validate_request(
            "check",
            params={"user": "passthru_user1@z", "pass": "geheim1" + "123456"},
        )
        assert response.json["result"]["value"] is True, response
