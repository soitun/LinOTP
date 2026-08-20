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
Unit tests for MonitorHandler.check_encryption
"""

import pytest

from linotp.lib.context import request_context
from linotp.lib.monitoring import MonitorHandler


class FakeHSM:
    """
    minimal fake security module that actually round-trips the value,
    so tests can selectively break either side of the roundtrip
    """

    def isReady(self):
        return True

    def encryptPassword(self, password: bytes) -> str:
        return "enc:" + password.decode("utf-8")

    def decryptPassword(self, crypted: str) -> bytes:
        return crypted.removeprefix("enc:").encode("utf-8")


class BrokenDecryptHSM(FakeHSM):
    """encrypts normally but decrypts to garbage - simulates a broken
    decrypt path (wrong key handle, degraded slot, etc.)"""

    def decryptPassword(self, crypted: str) -> bytes:
        return b"not-the-original-value"


class UnreachableDecryptHSM(FakeHSM):
    """encrypts normally but decrypting raises - simulates a
    disconnected/unreachable security module on the decrypt call"""

    def decryptPassword(self, crypted: str) -> bytes:
        msg = "hsm not reachable"
        raise RuntimeError(msg)


@pytest.mark.usefixtures("app")
class TestCheckEncryption:
    def test_check_encryption_roundtrip_ok(self):
        """encrypt and decrypt succeed and agree - encryption is verified"""
        request_context["hsm"] = {"obj": FakeHSM()}

        assert MonitorHandler().check_encryption() is True

    def test_check_encryption_decrypt_mismatch(self):
        """
        decryption succeeds but does not return the original plaintext -
        the roundtrip check must fail even though encryption itself works
        """
        request_context["hsm"] = {"obj": BrokenDecryptHSM()}

        assert MonitorHandler().check_encryption() is False

    def test_check_encryption_decrypt_unreachable(self):
        """
        the security module fails outright when decrypting - this must
        propagate as an error rather than be silently reported as ok
        """
        request_context["hsm"] = {"obj": UnreachableDecryptHSM()}

        with pytest.raises(RuntimeError):
            MonitorHandler().check_encryption()


# eof #
