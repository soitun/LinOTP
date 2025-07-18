#!/usr/bin/env python3

#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010-2019 KeyIdentity GmbH
#    Copyright (C) 2019-     netgo software GmbH
#
#    This file is part of LinOTP userid resolvers.
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

import json
import os
from unittest import TestCase, skip

from linotp.useridresolver.SQLIdResolver import IdResolver as SQLResolver


@skip("Broken 'no hsm defined in execution context'")
class TestSQLResolver(TestCase):
    y = None
    z = None
    proc = None

    def setUp(self):
        """
        This is run before each test. Read configuration from the given JSON file.
        """
        current_directory = os.path.dirname(os.path.abspath(__file__))

        sql_config = {
            "config": {
                "Driver": "sqlite",
                "Port": "",
                "Database": f"{current_directory}/data/linotp-users.sql",
                "Server": "",
                "User": "",
                "Password": "",
                "Table": "linotp_users",
                "Map": json.dumps(
                    {
                        "username": "username",
                        "userid": "id",
                        "password": "password",
                        "salt": "salt",
                        "givenname": "givenname",
                        "surname": "surname",
                        "email": "email",
                    }
                ),
            },
            "config2_map": json.dumps(
                {
                    "username": "username",
                    "userid": "username",
                    "password": "password",
                    "givenname": "givenname",
                    "surname": "surname",
                    "email": "email",
                }
            ),
            "config3_where": "(1 = 0 OR linotp_users.id > 2 ) AND 1 = 1",
        }

        config = sql_config["config"]
        config2 = config.copy()

        # A config with a differing Map (mapping string user IDs,
        # not numerical user IDs)

        config2["Map"] = sql_config["config2_map"]

        # Another config with a where clause (otherwise equals `config`)

        config3 = config.copy()
        config3["Where"] = sql_config["config3_where"]

        self.y = SQLResolver()
        self.y.loadConfig(config, "")
        self.z = SQLResolver()
        self.z.loadConfig(config2, "")
        self.w = SQLResolver()
        self.w.loadConfig(config3, "")

    def getUserList(self, obj, arg):
        """
        call obj.getUserList(), but check that we have no errors
        before returning.
        """
        res = obj.getUserList(arg)
        for item in res:
            for val in item.values():
                assert "-ERR" not in str(val)
        return res

    def test_sql_getUserId(self):
        """
        SQL: test the existance of the user1 and user2
        """
        res = self.y.getUserId("user1")
        print("uid (user1): ", res)
        assert res == 1

        assert self.y.getUserInfo(res).get("surname") == "Eins"

        res = self.y.getUserId("user2")
        print("uid (user2): ", res)
        assert res == 2

        assert self.y.getUserInfo(res).get("surname") == "Zwo"

        res = self.z.getUserId("user2")
        assert res == "user2"

    def test_sql_checkpass(self):
        """
        SQL: Check the password of user1 and user 2
        """
        assert self.y.checkPass(self.y.getUserId("user1"), "password")
        assert self.y.checkPass(self.y.getUserId("user2"), "password")

    def test_sql_checkpass_wo_salt(self):
        """
        SQL: Check the password of user1 and user 2 without column SALT
        """
        assert self.z.checkPass(self.z.getUserId("user1"), "password")
        assert self.z.checkPass(self.z.getUserId("user2"), "password")

    def test_get_search_fields(self):
        """
        SQL: Check the search field detection.
        """
        search_fields = self.y.getSearchFields()
        assert set(search_fields.keys()) == {
            "username",
            "userid",
            "password",
            "salt",
            "givenname",
            "surname",
            "email",
        }
        assert set(search_fields.values()) == {"numeric", "text"}

    def test_sql_search_escapes(self):
        """
        SQL: Check that the SQL wildcards are correctly escaped.
        """
        res1 = self.getUserList(self.y, {"givenname": "Pro%ent"})
        assert len(res1) == 1
        assert res1[0]["username"] == "user_3"

        res2 = self.getUserList(self.y, {"username": "user_3"})
        assert len(res2) == 1
        assert res2[0]["username"] == "user_3"

        res3 = self.getUserList(self.y, {"username": "user.3"})
        assert len(res3) == 2
        assert {s["username"] for s in res3} == {"user_3", "userx3"}

        res4 = self.getUserList(self.y, {"username": "user*"})
        assert len(res4) == 4

        res5 = self.getUserList(self.y, {"surname": "...."})
        assert {s["userid"] for s in res5} == {1, 3}

    def test_sql_complex_search(self):
        """
        SQL: test more complex search queries
        """
        res1 = self.getUserList(self.y, {"userid": "> 2"})
        assert len(res1) == 2
        assert {s["userid"] for s in res1} == {3, 4}

        res2 = self.getUserList(self.y, {"userid": "  <=   3  "})
        assert len(res2) == 3

        res3 = self.getUserList(self.y, {"userid": ">77"})
        assert res3 == []

    def test_sql_where(self):
        """
        SQL: test with a where clause. The where clause in `self.w` only gives us
        users with IDs > 2.
        """
        res1 = self.getUserList(self.w, {})
        assert {s["username"] for s in res1} == {"user_3", "userx3"}
        assert self.w.getUsername(1) == ""
        assert self.w.getUsername(2) == ""
        assert self.w.getUsername(3) == "user_3"
        assert self.w.getUsername(4) == "userx3"
        assert self.w.getUsername(5) == ""

        assert self.w.checkPass(self.w.getUserId("user_3"), "test")
        assert not self.w.checkPass(self.w.getUserId("user_3"), "falsch")

    def test_sql_getUserList(self):
        """
        SQL: testing the userlist
        """
        # all users are two users
        user_list = self.getUserList(self.y, {})
        assert len(user_list) == 4

        # there is only one user that ends with '1'
        user_list = self.getUserList(self.y, {"username": "*1"})
        assert len(user_list) == 1

    def test_sql_getUsername(self):
        """
        SQL: testing getting the username
        """
        assert self.y.getUsername(1) == "user1"
        assert self.y.getUsername(2) == "user2"
        assert self.y.getUsername(5) == ""

        # also test in the resolver with id as strings

        assert self.z.getUsername("user1") == "user1"
        assert self.z.getUsername("user2") == "user2"
        assert self.z.getUsername("user5") == ""


# eof #
