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
Tests the chunked data handling in the config
"""

from unittest.mock import Mock, patch

import flask
import pytest

from linotp.controllers.userservice import UserserviceController
from linotp.lib.user import User


class MockUserserviceController(UserserviceController):
    """
    for the unit test we need only the (static) method,
    so we omit the class constructor of a controller
    """

    def __init__(self):
        self.response = None


@patch("linotp.controllers.userservice.sendResult")
def test_otp_auth(mock_sendResult, app):
    """
    verify that the unbound local error is not raised anymore
    """

    class MockUser(User):
        def checkPass(self, password):
            return False

    mock_sendResult.return_value = "ok"

    user = MockUser("hans", "realm")
    passw = "test123"
    param = {"otp": "123456"}

    unboundLocalError_raised = False

    with app.app_context():
        flask.g.audit = {}

        try:
            userservice = MockUserserviceController()
            result = userservice._login_with_otp(user, passw, param)

        except UnboundLocalError as exx:
            unboundLocalError_raised = exx

    assert not unboundLocalError_raised, unboundLocalError_raised
    assert result == "ok"


@pytest.mark.parametrize(
    "prepend_pin_config,expected_combined_passw",
    [
        # the linotp config store persists booleans as the strings "True"/"False"
        ("True", "secretpw123456"),
        ("False", "123456secretpw"),
        # config unset -> must default to True
        (None, "secretpw123456"),
    ],
)
@patch("linotp.controllers.userservice.getTokenForUser")
@patch("linotp.controllers.userservice.get_selfservice_action_value")
@patch("linotp.controllers.userservice.ValidationHandler")
@patch("linotp.controllers.userservice.getFromConfig")
@patch("linotp.controllers.userservice.sendResult")
def test_login_with_otp_respects_prepend_pin_config(
    mock_sendResult,
    mock_getFromConfig,
    mock_ValidationHandler,
    mock_get_selfservice_action_value,
    mock_getTokenForUser,
    app,
    prepend_pin_config,
    expected_combined_passw,
):
    """
    _login_with_otp must combine the password and the otp in the same
    order as TokenClass.splitPinPass would split them again, based on
    the "PrependPin" config value - otherwise the otp check would fail.
    In order to get to userservice._login_with_otp(user, passw, param)
    mocking is needed.
    """

    class MockUser(User):
        def checkPass(self, password):
            return True

    def fake_getFromConfig(key, defVal=None, decrypt=False):
        if key == "PrependPin":
            return defVal if prepend_pin_config is None else prepend_pin_config
        return defVal

    mock_getFromConfig.side_effect = fake_getFromConfig
    mock_get_selfservice_action_value.return_value = False
    mock_getTokenForUser.return_value = []

    mock_vh_instance = Mock()
    mock_vh_instance.checkUserPass.return_value = (False, {})
    mock_ValidationHandler.return_value = mock_vh_instance

    mock_sendResult.return_value = "ok"

    user = MockUser("hans", "realm")
    passw = "secretpw"
    param = {"otp": "123456"}

    with app.app_context():
        flask.g.audit = {}
        flask.g.authUser = user

        userservice = MockUserserviceController()
        userservice._login_with_otp(user, passw, param)

    called_user, called_passw = mock_vh_instance.checkUserPass.call_args[0]
    assert called_user is user
    assert called_passw == expected_combined_passw


# eof
