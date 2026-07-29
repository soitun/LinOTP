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
Verify LinOTP supports single-character realm names, exercised through the
classic (non-v2) APIs: system/setRealm, system/getRealms, admin/userlist,
admin/init and admin/show. Realm names already have no backend minimum
length; these tests lock that in.
"""

from linotp.tests import TestController


class TestShortRealmNames(TestController):
    """single-char realm names."""

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

    def _realm_names(self):
        """the set of realm names known to LinOTP (lowercased)."""
        response = self.make_system_request("getRealms")
        return set(response.json["result"]["value"])

    def _userlist_count(self, realm):
        response = self.make_admin_request("userlist", params={"realm": realm})
        assert response.json["result"]["status"], response
        return len(response.json["result"]["value"])

    def _token_count_in_realm(self, realm):
        """number of tokens matched by admin/show for a realm filter."""
        response = self.make_admin_request("show", params={"realm": realm})
        return len(response.json["result"]["value"]["data"])

    def test_single_char_realm(self):
        """a single-character realm name is accepted and usable.

        The realm can be created (system/setRealm), is listed by
        system/getRealms and its users resolve via admin/userlist.
        """
        # create a brand-new realm with a one-character name, backed by an
        # existing resolver (myDefRes -> the def-passwd fixture, 27 users)
        response = self.create_realm(realm="z", resolvers=self.resolvers["myDefRes"])
        assert response.json["result"]["value"]

        # names are stored lowercased; the single-char realm is listed
        assert "z" in self._realm_names()

        # the single-char realm is usable: its users resolve
        assert self._userlist_count("z") == 27

    def test_single_char_realm_token_filter(self):
        """admin/show realm filter fully supports single-char realms.

        Sets up our own single-character realms (backed by the def-passwd
        resolver) and verifies the realm filter against every relevant
        fnmatch pattern class: exact match, prefix glob, single-char glob,
        character-class glob spanning several realms, the catch-all glob,
        and a non-existing realm.
        """
        def_res = self.resolvers["myDefRes"]
        for realm in ("x", "y", "w"):
            response = self.create_realm(realm=realm, resolvers=def_res)
            assert response.json["result"]["value"]

        # tokens in two of the three single-char realms; realm 'w' stays empty
        for user, realm, serial in (
            ("passthru_user1", "x", "PW-x"),
            ("passthru_user2", "y", "PW-y"),
        ):
            params = {
                "type": "pw",
                "otpkey": "geheim1",
                "user": user,
                "realm": realm,
                "serial": serial,
            }
            response = self.make_admin_request("init", params=params)
            assert response.json["result"]["value"]

        # exact single-char realm names
        assert self._token_count_in_realm("x") == 1
        assert self._token_count_in_realm("y") == 1
        # a valid single-char realm that holds no token
        assert self._token_count_in_realm("w") == 0
        # prefix glob on a single-char realm
        assert self._token_count_in_realm("x*") == 1
        # single-char wildcard matches any one-char realm -> both token realms
        assert self._token_count_in_realm("?") == 2
        # character-class glob spanning two specific single-char realms
        assert self._token_count_in_realm("[xy]") == 2
        assert self._token_count_in_realm("[yw]") == 1  # only realm y holds a token
        # catch-all wildcard
        assert self._token_count_in_realm("*") == 2
        # a non-existing realm still yields nothing
        assert self._token_count_in_realm("NON_EXISTING_REALM") == 0
