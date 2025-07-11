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
Tests a very small subset of linotp.lib.reply
"""

import json

import flask
import pytest

from linotp.lib import reply
from linotp.lib.error import ProgrammingError
from linotp.lib.reply import (
    _get_httperror_code_from_params,
    sendResultIterator,
)


@pytest.mark.usefixtures("app")
class TestReplyTestCase:
    @pytest.mark.parametrize(
        "querystring,result",
        [
            ("/?httperror=777", "777"),
            ("/?httperror=somestr", "500"),
            ("/?httperror", "500"),
            ("", None),
        ],
        ids=("set and valid", "set and invalid", "set and empty", "unset"),
    )
    def test_httperror_from_params(self, app, querystring, result):
        with app.test_request_context(querystring):
            httperror = _get_httperror_code_from_params()
            assert httperror == result

    @pytest.fixture
    def unicodeDecodeError(self, monkeypatch):
        """
        Simulate request parameters returning a UnicodeDecodeError
        """

        class fake_current_app:
            def getRequestParams(self):
                # Raise UnicodeDecodeError
                b"\xc0".decode("utf-8")

        monkeypatch.setattr(reply, "current_app", fake_current_app())

    @pytest.mark.usefixtures("unicodeDecodeError")
    def test_httperror_with_UnicodeDecodeError(self):
        with flask.current_app.test_request_context("/?httperror=555"):
            httperror = _get_httperror_code_from_params()
            assert httperror == "555"

    @pytest.mark.usefixtures("unicodeDecodeError")
    def test_httperror_with_UnicodeDecodeError_and_mult_param(self):
        # Raising exceptions on attribute access
        with flask.current_app.test_request_context("/?httperror=555&httperror=777"):
            httperror = _get_httperror_code_from_params()
            assert httperror == "777"

    def test_httperror_with_Exception(self, monkeypatch):
        class fake_current_app:
            def getRequestParams(self):
                msg = "Random exception"
                raise Exception(msg)

        monkeypatch.setattr(reply, "current_app", fake_current_app())

        with flask.current_app.test_request_context("/?httperror=555"):
            httperror = _get_httperror_code_from_params()
            assert httperror is None

    def test_response_iterator(self):
        """test if request context gets reinstated in sendResultIterator"""

        # we need to enclose bar into double qoutes,
        # because the json is assembled manually

        request_context_copy = {"one": '"one"', "two": '"two"'}

        def request_context_test_iterator():
            # this will raise an error if it is called
            # outside of request_context_safety
            res = request_context_copy.get("one")
            yield res
            res = request_context_copy.get("two")
            yield res

        try:
            res = sendResultIterator(
                obj=request_context_test_iterator(), rp=None, page=None
            )
        except ProgrammingError as exx:
            msg = "request_context was used outside of request_context_safety"
            raise AssertionError(msg) from exx

        result = ""
        for chunk in res:
            result += chunk

        result_dict = json.loads(result)
        value = result_dict.get("result", {}).get("value")

        assert value == ["one", "two"]

        try:
            res = sendResultIterator(obj=request_context_test_iterator(), rp=1, page=0)
        except ProgrammingError as exx:
            msg = "request_context was used outside of request_context_safety"
            raise AssertionError(msg) from exx

        result = ""
        for chunk in res:
            result += chunk

        result_dict = json.loads(result)
        value = result_dict.get("result", {}).get("value")

        assert value == ["one"]
