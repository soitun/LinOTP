# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
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
#    E-mail: linotp@keyidentity.com
#    Contact: www.linotp.org
#    Support: www.keyidentity.com
#


import pytest
import binascii
from hashlib import sha1


from linotp.tests import TestController
from linotp.lib.HMAC import HmacOtp


def get_otp(key, counter=None, digits=8):

    hmac = HmacOtp(digits=digits, hashfunc=sha1)
    return hmac.generate(counter=counter, key=binascii.unhexlify(key))


class TestUserserviceTokenTest(TestController):
    '''
    support userservice api endpoint to allow to verify an enrolled token
    '''

    def setUp(self):
        response = self.make_system_request(
            'setConfig', params={'splitAtSign': 'true'})
        assert 'false' not in response.body

        TestController.setUp(self)
        # clean setup
        self.delete_all_policies()
        self.delete_all_token()
        self.delete_all_realms()
        self.delete_all_resolvers()

        # create the common resolvers and realm
        self.create_common_resolvers()
        self.create_common_realms()

    def tearDown(self):
        TestController.tearDown(self)

    def test_verify_token(self):

        policy = {
            'name': 'T1',
            'action': 'enrollHMAC, delete, history, verify,',
            'user': ' passthru.*.myDefRes:',
            'realm': '*',
            'scope': 'selfservice'
        }
        response = self.make_system_request('setPolicy', params=policy)
        assert 'false' not in response, response

        auth_user = {
            'login': 'passthru_user1@myDefRealm',
            'password': 'geheim1'}

        serial = 'hmac123'

        params = {'type': 'hmac', 'genkey': '1', 'serial': serial}
        response = self.make_userselfservice_request(
            'enroll', params=params, auth_user=auth_user, new_auth_cookie=True)

        assert '"img": "<img ' in response, response

        seed_value = response.json['detail']['otpkey']['value']
        _, _, seed = seed_value.partition('//')

        otp = get_otp(seed, 1, digits=6)

        params = {'serial': serial, 'otp': otp}
        response = self.make_userselfservice_request(
            'verify', params=params, auth_user=auth_user)

        assert 'false' not in response

# eof #
