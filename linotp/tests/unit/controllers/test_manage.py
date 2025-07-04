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
# pylint: disable=redefined-outer-name
# pylint: disable=unused-argument


import flask
import pytest


@pytest.fixture
def index(adminclient):
    """
    For testing the index page.

    Returns the response directly. The context
    can be examined here by using the
    `context` fixture, or simply the usual flask objects
    """

    response = adminclient.get("/manage/")
    assert response.status_code == 200

    yield response


@pytest.fixture
def context(index):
    """
    Return index page context
    """
    return flask.g.request_context


@pytest.mark.parametrize(
    "tokentype",
    [
        "email",
        "qr",
    ],
)
def test_tokentypes(tokentype, context):
    """Test c.tokentypes is populated"""
    tokentypes = context["tokentypes"]
    assert tokentype in tokentypes
