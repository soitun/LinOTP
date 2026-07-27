# -*- coding: utf-8 -*-
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

""" unit test for complex policy comparisons """

import unittest
from datetime import datetime
from unittest.mock import patch

from linotp.lib.policy.evaluate import (
    action_compare,
    ip_list_compare,
    time_list_compare,
    user_list_compare,
    value_list_compare,
    wildcard_list_compare,
)
from linotp.lib.policy.filter import AttributeCompare, UserDomainCompare
from linotp.lib.user import User


def _matched(conditions, user):
    """Return only the boolean result of :func:`user_list_compare`."""
    _match_type, matched = user_list_compare(conditions, user)
    return matched


class TestCompare(unittest.TestCase):
    """
    unit tests for some comparison methods
     - will be moved into the unit tests
    """

    def test_value_list_compare(self):
        """
        test value list comparison
        """

        value_condition = ", , ,, "
        _mtype, res = value_list_compare(value_condition, "d")
        assert res == False

        value_condition = ", a , b ,,, c"
        _mtype, res = value_list_compare(value_condition, "d")
        assert res == False

        value_condition = ", a , b ,,, c"
        _mtype, res = value_list_compare(value_condition, "b")
        assert res

        value_condition = ", a , b=x ,,, c"
        _mtype, res = value_list_compare(value_condition, "b")
        assert res

        value_condition = ", a , b=x ,,, c=x"
        _mtype, res = value_list_compare(value_condition, "b=a")
        assert res == False

        value_condition = ", a , b ,,, c=x, ,"
        _mtype, res = value_list_compare(value_condition, "b=a")
        assert res == False

    def test_wildcard_list_compare(self):
        """
        test wildcard list compare
        """

        value_condition = "read, write, execute, "
        _mtype, res = wildcard_list_compare(value_condition, "write")
        assert res

        value_condition = " , ,,,,, , ,,     ,,  ,"
        _mtype, res = wildcard_list_compare(value_condition, "write")
        assert res == False

        value_condition = ""
        _mtype, res = wildcard_list_compare(value_condition, "write")
        assert res == False

        value_condition = "* , write"
        _mtype, res = wildcard_list_compare(value_condition, "write")
        assert res

    def test_time_compare(self):
        """
        test the time comparison method
        """
        time_conditions0 = (
            # allowed all time
            "*   *    * * * *; "
            # not allowed past 17 o clock
            "-* 18-23 * * * *; "
            # not allowed before 7 o clock
            "!*  0-6  * * * *"
        )

        time_conditions1 = (
            # allowed between 7 and 17 o clock
            # same as above but without negation
            "*  7-17  * * * *; "
        )

        time_conditions_set = []
        time_conditions_set.append(time_conditions0)
        time_conditions_set.append(time_conditions1)

        for time_conditions in time_conditions_set:
            # datetime args
            # datetime(year, month, day[, hour[, minute[, second[, micro ..

            _match_type, match = time_list_compare(
                time_conditions, datetime(2016, 12, 14, 15, 30)
            )  # 15:30
            assert match

            _match_type, match = time_list_compare(
                time_conditions, datetime(2016, 12, 14, 18, 0)
            )  # 18:00
            assert not match

            _match_type, match = time_list_compare(
                time_conditions, datetime(2016, 12, 14, 6, 0)
            )  # 6:00
            assert not match

        return

    def test_ip_compare(self):
        """
        test the ip comparison method
        """

        ip_conditions = (
            # all of subnet
            "192.168.0.0/16, "
            # but not this one
            "-192.168.17.15, "
            # and subnet is not allowed too
            "!192.168.16.0/24"
        )

        _match_type, match = ip_list_compare(ip_conditions, "127.0.0.1")
        assert not match

        _match_type, match = ip_list_compare(ip_conditions, "192.168.12.13")
        assert match

        _match_type, match = ip_list_compare(ip_conditions, "192.168.17.15")
        assert not match

        _match_type, match = ip_list_compare(ip_conditions, "192.168.16.152")
        assert not match

    def test_user_compare(self):
        """
        test the user list comparison method
        """

        user_conditions = (
            # exact name match
            "Hugo, "
            # negative test
            "!Emma, "
            # wildcard realm test
            "*@realm, "
            # wildcard name test
            "a*, "
            # negative wildcad name test
            "!*z"
        )

        hugo = User("Hugo", "realm")

        match_type, match = user_list_compare(user_conditions, hugo)
        assert match
        assert match_type == "exact:match"

        emma = User("Emma")
        match_type, match = user_list_compare(user_conditions, emma)
        assert not match
        assert match_type == "not:match"

        betonz = User("betonz", "realm")
        match_type, match = user_list_compare(user_conditions, betonz)
        assert not match
        assert match_type == "not:match"

        wanda = User("wanda", "realm")
        match_type, match = user_list_compare(user_conditions, wanda)
        assert match
        assert match_type == "regex:match"

        wanda2 = "wanda@realm"
        match_type, match = user_list_compare(user_conditions, wanda2)
        assert match
        assert match_type == "regex:match"

        return

    def test_user_compare_login_regex(self):
        """login part is a whole-string, case sensitive regular expression.

        Locks in that the user name is matched anchored at both ends and
        case sensitively, and that '*' works as a convenience wildcard.
        """

        # anchored at start and end: only the whole login matches
        assert _matched("hugo", User("hugo", "realm"))
        assert not _matched("hug", User("hugo", "realm"))
        assert not _matched("ugo", User("hugo", "realm"))
        assert not _matched("hugo", User("hugo2", "realm"))

        # case sensitive
        assert not _matched("hugo", User("Hugo", "realm"))
        assert _matched("Hugo", User("Hugo", "realm"))

        # '*' convenience wildcard, and an explicit '.*' regex
        assert _matched("*", User("anybody", "realm"))
        assert _matched("hub*", User("huber", "realm"))
        assert _matched("huber.*", User("huber", "realm"))
        assert not _matched("huber.*", User("hub", "realm"))

    def test_user_compare_realm(self):
        """USER@REALM matches the login against the realm.

        Locks in that the part after '@' is matched against the realm (case
        insensitively, as a regular expression), that '*' is required as the
        user part to select every user in a realm, and that an empty user part
        matches nobody.
        """

        # login before '@', realm after '@'
        assert _matched("john@example", User("john", "example"))
        assert not _matched("john@example", User("john", "other"))

        # '*@realm' selects every user in the realm ...
        assert _matched("*@example", User("hugo", "example"))
        # ... while an empty user part ('@realm') matches nobody
        assert not _matched("@example", User("hugo", "example"))

        # realm match is case insensitive
        assert _matched("*@EXAMPLE", User("hugo", "example"))

        # the realm part is a regular expression: '.' is a wildcard ...
        assert _matched("*@my.realm", User("x", "myXrealm"))
        # ... and must be escaped to match a literal dot
        assert not _matched(r"*@my\.realm", User("x", "myXrealm"))
        assert _matched(r"*@my\.realm", User("x", "my.realm"))

        # a regex login part can be combined with a realm
        assert _matched("_(prod|dev)@example", User("_prod", "example"))
        assert _matched("_(prod|dev)@example", User("_dev", "example"))
        assert not _matched("_(prod|dev)@example", User("_test", "example"))
        assert not _matched("_(prod|dev)@example", User("_prod", "other"))

    def test_user_compare_realm_binding(self):
        """USER@REALM binds a user pattern to a specific realm.

        Verifies that several entries can target different users in different
        realms in one policy - which the realm field cannot express (docs
        examples 'alice@sales, bob@support' and the selfservice example
        '*@onedomain, ^ext.*@seconddomain').
        """

        # specific users bound to specific realms (no cross-pairing)
        cond = "alice@sales, bob@support"
        assert _matched(cond, User("alice", "sales"))
        assert _matched(cond, User("bob", "support"))
        assert not _matched(cond, User("alice", "support"))
        assert not _matched(cond, User("bob", "sales"))

        # wildcard for one realm, regex-restricted users for another
        cond = "*@sales, ^ext.*@support"
        assert _matched(cond, User("anyone", "sales"))
        assert _matched(cond, User("extbob", "support"))
        assert not _matched(cond, User("bob", "support"))
        assert not _matched(cond, User("anyone", "other"))

    def test_user_compare_negation(self):
        """'!' and '-' prefixes exclude users.

        Locks in that a matched negative condition excludes the user, that a
        negation on its own matches nobody, and that '-' behaves like '!'.
        """

        # a negation on its own matches nobody
        assert not _matched("!user1", User("user1", "realm"))
        assert not _matched("!user1", User("other", "realm"))

        # combined with a positive selector it means "all except"
        assert not _matched("*, !user1", User("user1", "realm"))
        assert _matched("*, !user1", User("other", "realm"))

        # '-' is an alias for '!'
        assert not _matched("*, -user1", User("user1", "realm"))
        assert _matched("*, -user1", User("other", "realm"))

    def test_user_compare_negation_with_resolver(self):
        """'ad1:, !hugo' - every user of resolver 'ad1' except 'hugo'.

        Uses real User objects with getUserInfo/getResolverList patched, since
        resolver matching reads the user's info from the resolver.
        """
        with patch(
            "linotp.lib.resolver.getResolverList", return_value={"ad1": {}}
        ), patch.object(User, "getUserInfo", return_value={"userid": "1"}):
            assert _matched("ad1:, !hugo", User("alice", "realm"))
            assert not _matched("ad1:, !hugo", User("hugo", "realm"))

    def test_user_compare_attribute(self):
        """user attribute matching: exists / '==' / '!=' / '~=' operators.

        Drives AttributeCompare with a stub user, because attribute matching
        reads the user's info from the resolver (getUserInfo). The optional
        selector before '#' still filters by login name and realm.
        """

        class StubUser:
            def __init__(self, login, realm, info):
                self.login = login
                self.realm = realm
                self._info = info

            def getUserInfo(self, resolver=None):
                return self._info

            def get_full_qualified_names(self):
                return ["%s@%s" % (self.login, self.realm), self.login]

        def matches(user_def, login, realm, info):
            return AttributeCompare().compare(
                StubUser(login, realm, info), user_def
            )

        # exists: attribute present / absent
        assert matches("#mobile", "u", "r", {"mobile": "12"})
        assert not matches("#mobile", "u", "r", {"email": "x"})

        # '==' exact (stripped) equality
        assert matches(
            "#department == sales", "u", "r", {"department": "sales"}
        )
        assert not matches(
            "#department == sales", "u", "r", {"department": "eng"}
        )

        # '!=' inequality
        assert matches("#department != sales", "u", "r", {"department": "eng"})
        assert not matches(
            "#department != sales", "u", "r", {"department": "sales"}
        )

        # '~=' regex search (substring, not anchored)
        assert matches("#mobile ~= 123", "u", "r", {"mobile": "49123456"})
        assert not matches("#mobile ~= 123", "u", "r", {"mobile": "999"})
        assert matches("#mobile ~= ^123", "u", "r", {"mobile": "123456"})
        assert not matches("#mobile ~= ^123", "u", "r", {"mobile": "49123"})

        # selector before '#' also filters by login (regex) and realm
        assert matches(
            "pas.*@myrealm#mobile ~= 123",
            "pascal",
            "myrealm",
            {"mobile": "49123"},
        )
        assert not matches(
            "pas.*@myrealm#mobile ~= 123",
            "pascal",
            "other",
            {"mobile": "49123"},
        )
        assert not matches(
            "pas.*@myrealm#mobile ~= 123",
            "bob",
            "myrealm",
            {"mobile": "49123"},
        )

        # a resolver selector before '#' (user must exist in the resolver)
        with patch(
            "linotp.lib.resolver.getResolverList", return_value={"ad1": {}}
        ):
            assert matches(
                "ad1:#mobile ~= 123", "someone", "r", {"mobile": "49123"}
            )
            assert not matches(
                "ad1:#department == sales",
                "someone",
                "r",
                {"mobile": "49123"},
            )

    def test_user_compare_resolver(self):
        """'resolver:' / 'USER.resolver:' selects users by resolver.

        Locks in that the resolver name must be an existing resolver (exact
        match) and that an optional USER prefix is a regex on the login.
        getResolverList is patched and the user is stubbed, because resolver
        matching reads the user's info from the resolver.
        """

        class StubUser:
            def __init__(self, login, realm="realm"):
                self.login = login
                self.realm = realm

            def getUserInfo(self, resolver=None):
                # a non-empty user info means "user exists in this resolver"
                return {"userid": "1"}

            def get_full_qualified_names(self):
                return ["%s@%s" % (self.login, self.realm), self.login]

        def matches(user_def, login):
            return UserDomainCompare().exists(StubUser(login), user_def)

        with patch(
            "linotp.lib.resolver.getResolverList",
            return_value={"resolv1": {}},
        ):
            # existing vs unknown resolver
            assert matches("resolv1:", "hugo")
            assert not matches("nope:", "hugo")

            # USER.resolver: the user part is a regex on the login
            assert matches("^devel.*.resolv1:", "develX")
            assert not matches("^devel.*.resolv1:", "bob")

    def test_action_compare(self):
        match_type, res = action_compare(
            'voice_message = "Sir, your otp={otp}" ,'
            " voice_language = ' Sir, your otp is {otp}' , ",
            "voice_message",
        )
        assert res
        assert match_type == "exact:match"

        match_type, res = action_compare(
            'voice_message = "Sir, your otp={otp}" ,'
            " voice_language = ' Sir, your otp is {otp}' , ",
            " your otp",
        )
        assert not res
        assert match_type == "not:match"
