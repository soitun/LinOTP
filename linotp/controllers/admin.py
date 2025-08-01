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
admin controller - interfaces to administrate LinOTP
"""

import json
import logging
from datetime import datetime

from flask import Response, current_app, g, request, stream_with_context
from flask_babel import gettext as _
from werkzeug.datastructures import FileStorage

from linotp.controllers.base import BaseController, JWTMixin, methods
from linotp.lib import deprecated_methods
from linotp.lib.audit.base import get_token_num_info
from linotp.lib.challenges import Challenges
from linotp.lib.context import request_context
from linotp.lib.error import ParameterError, TokenAdminError
from linotp.lib.ImportOTP.oath import parseOATHcsv
from linotp.lib.ImportOTP.safenet import parseSafeNetXML
from linotp.lib.ImportOTP.yubico import parseYubicoCSV
from linotp.lib.policy import (
    PolicyException,
    checkPolicyPost,
    checkPolicyPre,
    getOTPPINEncrypt,
)
from linotp.lib.realm import getRealms
from linotp.lib.reply import (
    sendCSVResult,
    sendError,
    sendQRImageResult,
    sendResult,
    sendResultIterator,
    sendXMLError,
    sendXMLResult,
)
from linotp.lib.reporting import token_reporting
from linotp.lib.resolver import get_resolver_class, getResolverInfo
from linotp.lib.token import (
    TokenHandler,
    get_token,
    get_tokens,
    getTokenRealms,
    resetToken,
    setPin,
    setPinUser,
    setRealms,
)
from linotp.lib.tokeniterator import TokenIterator
from linotp.lib.type_utils import boolean
from linotp.lib.user import (
    User,
    getSearchFields,
    getUserFromRequest,
    getUserListIterators,
)
from linotp.lib.useriterator import iterate_users
from linotp.lib.util import getLowerParams
from linotp.model import db
from linotp.tokens import tokenclass_registry

log = logging.getLogger(__name__)


class AdminController(BaseController, JWTMixin):
    """
    The linotp.controllers are the implementation of the web-API to talk to
    the LinOTP server.
    The AdminController is used for administrative tasks like adding tokens
    to LinOTP, assigning tokens or revoking tokens.
    The functions of the AdminController are invoked like this

        https://server/admin/<functionname>

    The functions are described below in more detail.
    """

    def __before__(self, *args, **kwargs):
        """
        __before__ is called after every action
        """

        g.reporting = {"realms": set()}

    @staticmethod
    def __after__(response):
        """
        __after__ is called after every action

        :param response: the previously created response - for modification
        :return: return the response
        """

        action = request_context["action"]

        try:
            auth_user = getUserFromRequest()
            g.audit["administrator"] = auth_user

            # ------------------------------------------------------------- --

            # show the token usage counter for the actions which change the
            # numbers of tokens

            if auth_user and action in [
                "assign",
                "unassign",
                "enable",
                "disable",
                "init",
                "loadtokens",
                "copyTokenUser",
                "losttoken",
                "remove",
                "tokenrealm",
            ]:
                event = "token_" + action

                realms_to_report = g.reporting["realms"]
                if realms_to_report:
                    token_reporting(event, realms_to_report)

                g.audit["action_detail"] += get_token_num_info()

            # ------------------------------------------------------------- --

            current_app.audit_obj.log(g.audit)
            db.session.commit()
            return response

        except Exception as exx:
            log.error("[__after__::%r] exception %r", action, exx)
            db.session.rollback()
            return sendError(exx)

    @deprecated_methods(["POST"])
    def getTokenOwner(self):
        """
        provide the userinfo of the token, which is specified as serial

        :param serial: the serial number of the token
        :returns:
            a json result with a boolean status and request result
        """

        ret = {}
        try:
            serial = self.request_params["serial"]
            g.audit["serial"] = serial

            # check admin authorization
            checkPolicyPre("admin", "tokenowner", self.request_params)
            th = TokenHandler()
            owner = th.getTokenOwner(serial)
            if owner.info:
                ret = owner.info
                token = get_token(serial)
                g.audit["success"] = 1
                g.audit["token_type"] = token.type
                g.audit["user"] = ret.get("username")
                g.audit["realm"] = ", ".join(token.getRealms())
            else:
                g.audit["success"] = 0

            db.session.commit()
            return sendResult(ret)

        except PolicyException as pe:
            log.error("Error getting token owner. Exception was %r", pe)
            db.session.rollback()
            return sendError(pe, 1)

        except Exception as exx:
            log.error("Error getting token owner. Exception was %r", exx)
            db.session.rollback()
            return sendError(exx, 1)

    @staticmethod
    def _parse_tokeninfo(tok):
        """
        Parse TokenInfo to JSON
        and format validity periode date fields to isoformat
        """

        token_info = tok["LinOtp.TokenInfo"]

        info = json.loads(token_info) if token_info else {}

        for field in ["validity_period_end", "validity_period_start"]:
            if field in info:
                date = datetime.strptime(info[field], "%d/%m/%y %H:%M")
                info[field] = date.isoformat()

        tok["LinOtp.TokenInfo"] = info

    @deprecated_methods(["POST"])
    def show(self):
        """
        displays the list of the available tokens


        :param serial:   (optional)  only this serial will be displayed
        :param user:     (optional)  only the tokens of this user will be
                                  displayed. If the user does not exist,
                                  linotp will search tokens of users, who
                                  contain this substring.
                        **TODO:** This can be very time consuming an will be
                                  changed in the next release to use wildcards.
        :param filter:   (optional)  takes a substring to search in table token
                                  columns
        :param viewrealm:  (optional)  takes a realm, only the tokens in this
                                    realm will be displayed
        :param realm:  (optional)  alias to the viewrealm
        :param sortby:   (optional)  sort the output by column
        :param sortdir:  (optional)  asc/desc
        :param page:     (optional)  reqeuest a certain page
        :param pagesize: (optional)  limit the number of returned tokens
        :param user_fields:  (optional)  additional user fields from the userid resolver of the owner (user)
        :param outform:  (optional)  if set to "csv", than the token list will be given in CSV
        :param tokeninfo_format:  (optional)  if set to "json", this will be supplied in embedded JSON
                                 otherwise, string format is returned with dates in format
                                 DD/MM/YYYY TODO

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned
        """

        param = self.request_params
        try:
            serial = param.get("serial")
            page = param.get("page")
            filter = param.get("filter")
            sort = param.get("sortby")
            dir = param.get("sortdir")
            psize = param.get("pagesize")
            realm = param.get("viewrealm", param.get("realm", ""))
            ufields = param.get("user_fields")
            output_format = param.get("outform")
            is_tokeninfo_json = param.get("tokeninfo_format") == "json"

            user_fields = [u.strip() for u in ufields.split(",")] if ufields else []

            user = request_context["RequestUser"]

            # check admin authorization
            res = checkPolicyPre("admin", "show", param, user=user)

            # check if policies are active at all
            # If they are not active, we are allowed to SHOW any tokens.
            filterRealm = res["realms"] if res["active"] and res["realms"] else ["*"]

            if realm:
                # If the admin wants to see only one realm, then do it:
                log.debug("Only tokens in realm %s will be shown", realm)
                if realm in filterRealm or "*" in filterRealm:
                    filterRealm = [realm]

            log.info(
                "[show] admin >%s< may display the following realms: %r",
                res["admin"],
                filterRealm,
            )

            toks = TokenIterator(
                user,
                serial,
                page,
                psize,
                filter,
                sort,
                dir,
                filterRealm,
                user_fields,
            )

            g.audit["success"] = True
            g.audit["info"] = f"realm: {filterRealm}, filter: {filter!r}"

            # put in the result
            result = {}

            # now row by row
            lines = []
            for tok in toks:
                if is_tokeninfo_json:
                    self._parse_tokeninfo(tok)

                lines.append(tok)

            result["data"] = lines
            result["resultset"] = toks.getResultSetInfo()

            db.session.commit()

            if output_format == "csv":
                return sendCSVResult(result)
            else:
                return sendResult(result)

        except PolicyException as pe:
            log.error("[show] policy failed: %r", pe)
            db.session.rollback()
            return sendError(pe, 1)

        except Exception as exx:
            log.error("[show] failed: %r", exx)
            db.session.rollback()
            return sendError(exx)

    ########################################################
    @methods(["POST"])
    def remove(self):
        """
        deletes either a certain token given by serial or all tokens of a user

        :param serial:  - the serial number of the token
        :param user:     (optional) , will delete all tokens of a user

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """

        param = self.request_params

        try:
            serials = param.get("serial", set())
            if isinstance(serials, str):
                serials = {serials}
            elif isinstance(serials, list):
                serials = set(serials)

            user = request_context["RequestUser"]

            if not serials and not user:
                msg = "missing parameter user or serial!"
                raise ParameterError(msg)

            if user:
                tokens = get_tokens(user)
                serials.update(token.getSerial() for token in tokens)

            g.audit["serial"] = " ".join(serials)

            realms = {
                realm for serial in set(serials) for realm in getTokenRealms(serial)
            }

            g.audit["realm"] = f"{realms!r}"

            log.info(
                "[remove] removing token with serial %r for user %r",
                serials,
                user.login,
            )

            ret = 0
            check_params = {}
            check_params.update(param)

            realms = set()
            users = set()
            token_types = set()
            th = TokenHandler()
            for serial in serials:
                # check admin authorization
                check_params["serial"] = serial
                checkPolicyPre("admin", "remove", check_params)

                token = get_token(serial)
                token_realms = token.getRealms()
                realms.update(token_realms)
                g.reporting["realms"].update(token_realms or ["/:no realm:/"])
                users.add(token.getUsername())
                token_types.add(token.type)

                ret += th.removeToken(user, serial)

            g.audit["success"] = 1 if len(serials) == ret else 0
            g.audit["token_type"] = ", ".join(token_types)
            g.audit["user"] = ", ".join(users)
            g.audit["realm"] = ", ".join(realms)

            opt_result_dict = {}

            # if not token could be removed, create a response detailed
            if ret == 0:
                msg = (
                    f"No tokens for this user {user.login!r}"
                    if user
                    else f"No token with serials {serials!r}"
                )

                opt_result_dict["message"] = msg

            db.session.commit()
            return sendResult(ret, opt=opt_result_dict)

        except PolicyException as pe:
            log.error("[remove] policy failed %r", pe)
            db.session.rollback()
            return sendError(pe, 1)

        except Exception as exx:
            log.error("[remove] failed! %r", exx)
            db.session.rollback()
            return sendError(exx)

    ########################################################
    @methods(["POST"])
    def enable(self):
        """
        enables a token or all tokens of a user

        :param serial: (optional), the token serial number
        :param user: (optional), will enable all tokens of a user

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """

        param = self.request_params
        try:
            serial = param.get("serial")
            user = request_context["RequestUser"]
            g.audit["serial"] = serial

            # check admin authorization
            checkPolicyPre("admin", "enable", param, user=user)

            th = TokenHandler()
            log.info(
                "[enable] enable token with serial %s for user %s@%s.",
                serial,
                user.login,
                user.realm,
            )
            ret = th.enableToken(True, user, serial)

            g.audit["success"] = ret

            tokens = get_tokens(user, serial=serial)
            g.audit["serial"] = (
                serial
                if serial
                else " ".join([t.token.LinOtpTokenSerialnumber for t in tokens])
            )
            g.audit["token_type"] = ", ".join([t.type for t in tokens])
            g.audit["user"] = ", ".join([t.getUsername() for t in tokens])
            # get all token realms - including "/:no realm:/"
            # if a token was in no realm (for reporting)
            realms = [
                realm
                for token in tokens
                for realm in (token.getRealms() or ["/:no realm:/"])
            ]
            # replace "/:no realm:/" by empty string for audit
            audit_realms = [
                realm if realm != "/:no realm:/" else "" for realm in realms
            ]
            g.audit["realm"] = ", ".join(audit_realms)
            g.reporting["realms"] = set(realms)

            opt_result_dict = {}
            if ret == 0 and serial:
                opt_result_dict["message"] = f"No token with serial {serial}"
            elif ret == 0 and user:
                opt_result_dict["message"] = "No tokens for this user"

            checkPolicyPost("admin", "enable", param, user=user)

            db.session.commit()
            return sendResult(ret, opt=opt_result_dict)

        except PolicyException as pe:
            log.error("[enable] policy failed %r", pe)
            db.session.rollback()
            return sendError(pe, 1)

        except Exception as exx:
            log.error("[enable] failed: %r", exx)
            db.session.rollback()
            log.error("[enable] error enabling token")
            return sendError(exx, 1)

    ########################################################
    @deprecated_methods(["POST"])
    def getSerialByOtp(self):
        """
        searches for the token, that generates the given OTP value.
        The search can be restricted by several criteria

        :param otp:      (required). Will search for the token, that produces this OTP value
        :param type:     (optional), will only search in tokens of type
        :param realm:    (optional) only search in this realm
        :param assigned: (optional) 1: only search assigned tokens, 0: only search unassigned tokens

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """

        ret = {}
        param = self.request_params

        try:
            try:
                otp = param["otp"]
            except KeyError as exx:
                msg = "Missing parameter: 'otp'"
                raise ParameterError(msg) from exx

            typ = param.get("type")
            realm = param.get("realm")
            assigned = param.get("assigned")

            serial = ""
            username = ""

            # check admin authorization
            checkPolicyPre("admin", "getserial", param)
            th = TokenHandler()
            serial, username, resolverClass = th.get_serial_by_otp(
                None, otp, 10, typ=typ, realm=realm, assigned=assigned
            )
            log.debug("[getSerialByOtp] found %s with user %s", serial, username)

            if serial != "":
                checkPolicyPost("admin", "getserial", {"serial": serial})

            g.audit["success"] = 0
            g.audit["serial"] = serial
            if serial:
                token = get_token(serial)
                g.audit["success"] = 1
                g.audit["token_type"] = token.type
                g.audit["user"] = token.getUsername()
                g.audit["realm"] = ", ".join(token.getRealms())

            ret["success"] = True
            ret["serial"] = serial
            ret["user_login"] = username
            ret["user_resolver"] = resolverClass

            db.session.commit()
            return sendResult(ret, 1)

        except PolicyException as pe:
            log.error("[disable] policy failed %r", pe)
            db.session.rollback()
            return sendError(pe, 1)

        except Exception as exx:
            g.audit["success"] = 0
            db.session.rollback()
            log.error("[getSerialByOtp] error: %r", exx)
            return sendError(exx, 1)

    ########################################################
    @methods(["POST"])
    def disable(self):
        """
        disables a token given by serial or all tokens of a user

        :param serial: the token serial
        :param user: the user for whom all tokens will be disabled

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """

        param = self.request_params
        try:
            serial = param.get("serial")
            user = request_context["RequestUser"]
            g.audit["serial"] = serial

            # check admin authorization
            checkPolicyPre("admin", "disable", param, user=user)

            th = TokenHandler()
            log.info(
                "[disable] disable token with serial %s for user %s@%s.",
                serial,
                user.login,
                user.realm,
            )
            ret = th.enableToken(False, user, serial)

            tokens = get_tokens(user, serial=serial)

            g.audit["success"] = ret
            g.audit["serial"] = (
                serial
                if serial
                else " ".join([t.token.LinOtpTokenSerialnumber for t in tokens])
            )
            g.audit["token_type"] = ", ".join([t.type for t in tokens])
            g.audit["user"] = user.login or ", ".join([t.getUsername() for t in tokens])
            # get all token realms - including "/:no realm:/"
            # if a token was in no realm (for reporting)
            realms = [
                realm
                for token in tokens
                for realm in (token.getRealms() or ["/:no realm:/"])
            ]
            # replace "/:no realm:/" by empty string for audit
            audit_realms = [
                realm if realm != "/:no realm:/" else "" for realm in realms
            ]
            g.audit["realm"] = ", ".join(audit_realms)
            g.reporting["realms"] = set(realms)

            opt_result_dict = {}
            if ret == 0 and serial:
                opt_result_dict["message"] = f"No token with serial {serial}"
            elif ret == 0 and user:
                opt_result_dict["message"] = "No tokens for this user"

            db.session.commit()
            return sendResult(ret, opt=opt_result_dict)

        except PolicyException as pe:
            log.error("[disable] policy failed %r", pe)
            db.session.rollback()
            return sendError(pe, 1)

        except Exception as exx:
            log.error("[disable] failed! %r", exx)
            db.session.rollback()
            return sendError(exx, 1)

    #######################################################
    @deprecated_methods(["POST"])
    def check_serial(self):
        """

        This function checks, if a given serial will be unique.
        It returns True if the serial does not yet exist and
        new_serial as a new value for a serial, that does not exist, yet


        :param serial: the serial to be checked

        :return:
            a json result with a boolean status and a new suggestion for the serial

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """

        try:
            try:
                serial = self.request_params["serial"]
                g.audit["serial"] = serial
            except KeyError as exx:
                msg = "Missing parameter: 'serial'"
                raise ParameterError(msg) from exx

            log.info("[check_serial] checking serial %s", serial)
            th = TokenHandler()
            (unique, new_serial) = th.check_serial(serial)

            g.audit["success"] = True
            g.audit["action_detail"] = f"{unique!r} - {new_serial!r}"

            db.session.commit()
            return sendResult({"unique": unique, "new_serial": new_serial}, 1)

        except PolicyException as pe:
            log.error("[check_serial] policy failed %r", pe)
            db.session.rollback()
            return sendError(pe, 1)

        except Exception as exx:
            log.error("[check_serial] failed! %r", exx)
            db.session.rollback()
            return sendError(exx)

    ########################################################
    @methods(["POST"])
    def init(self):
        """
        creates a new token.

        common arguments:

        we either need otpkey or genkey for key generation

        :param otpkey: (required) the used token seed
        :param genkey: (required) =1, if an hmac key should be generated instead.

        the common reply includes the following components:

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned

        to customize your token you can use the following parameters:

        :param keysize: (optional) either 20 or 32. Default is 20
        :param serial: (optional) the serial number / identifier of the token, if no serial is
            provided, it will be generated
        :param description: (optional)
        :param pin: (optional) the pin of the user pass
        :param user: (optional) the user the token will be assigned to
        :param realm: (optional) the realm of the user
        :param type: (optional) the type of the token, if no type is provided an hmac token will
            be generated
        :param tokenrealm: (optional) the realm a token should be put into
        :param otplen: (optional) the number of digits of the OTP value. Default length is 6
        :param hashlib: (optional) the hash algorithm used in the mac
                calculation (sha512, sha256, sha1). default is sha256

        the usage scope can be managed with the following parameters:

        :param scope: (optional) the path(s) the token can be used for
        :param rollout: (optional) replaces scope={“path”:[“userservice”]} for rollout tokens

        **token-type-specific parameters**

        email token arguments: for generating email tokens type=email you can specify the
        following parameters:

        :param email_address: (required) the address the otp email will be sent to

        forward token arguments: for generating forward tokens type=forward you can specify the
        following parameters:

        :param forward.serial: (required) the serial of the target-token

        ocra2 token arguments: for generating OCRA2 tokens type=ocra2 you can specify the
        following parameters:

        :param ocrasuite: (optional) - if you do not want to use the default
                ocra suite OCRA-1:HOTP-SHA256-8:QA644
        :param sharedsecret: (optional) if you are in Step0 of enrolling an
                OCRA2 token the sharedsecret=1 specifies, that you want to generate a shared secret4
        :param activationcode: (optional) if you are in Step1 of enrolling
            an OCRA2 token you need to pass the activation code, that was generated in the QRTAN-App

        radius token arguments: for generating radius tokens type=radius you can specify the
        following parameters:

        :param radius.server: (required) the URL of the radius server
        :param radius.local_checkpin: (required) if the pin should be checked locally or on the target server
        :param radius.user: (required) the user on the radius server
        :param radius.secret: (required) the shared secret of the radius server

        remote token arguments: for generating remote tokens type=remote you can specify the
        following parameters:

        :param remote.server: (required) the linotp server the requests will be sent to
        :param remote.local_checkpin: (required) if the pin should be checked locally or on the target server
        :param remote.serial: (required) the serial of the target token on the remote server
        :param remote.user: (optional) the user on the remote server
        :param remote.realm: (optional) the realm of the remote user
        :param remote.resconf: (optional) the resolver for the remote user

        sms token arguments: for generating sms tokens type=sms you can specify the
        following parameters:

        :param phone: (required) the phone number the sms will be sent to

        totp token arguments: for generating totp tokens type=totp you can specify the
        following parameters:

        :param timestep: (required) the time in seconds between new otps

        yubico token arguments: for generating yubico tokens type=yubico you can specify the
        following parameters:

        :param yubico.tokenid: (required) the 12-character tokenid of the yubico token

        +---------+--------------------------------------------------------------------------------+
        | type    | required parameters                                                            |
        +=========+================================================================================+
        | hmac    | optkey/genkey=1                                                                |
        +---------+--------------------------------------------------------------------------------+
        | totp    | optkey/genkey=1, type=totp, timestep                                           |
        +---------+--------------------------------------------------------------------------------+
        | qr      | type=qr                                                                        |
        +---------+--------------------------------------------------------------------------------+
        | push    | type=push                                                                      |
        +---------+--------------------------------------------------------------------------------+
        | pw      | type=pw, otpkey                                                                |
        +---------+--------------------------------------------------------------------------------+
        | dpw     | type=dpw, otpkey                                                               |
        +---------+--------------------------------------------------------------------------------+
        | email   | type=email, email_address                                                      |
        +---------+--------------------------------------------------------------------------------+
        | motp    | type=motp, otpkey                                                              |
        +---------+--------------------------------------------------------------------------------+
        | sms     | type=sms, phone                                                                |
        +---------+--------------------------------------------------------------------------------+
        | voice   | type=voice, phone                                                              |
        +---------+--------------------------------------------------------------------------------+
        | ocra    | type=ocra2, sharedsecret, ocrasuite, otpkey                                    |
        +---------+--------------------------------------------------------------------------------+
        | yubikey | type=yubico, yubico.tokenid                                                    |
        +---------+--------------------------------------------------------------------------------+
        | forward | type=forward, forward.serial                                                   |
        +---------+--------------------------------------------------------------------------------+
        | radius  | type=radius, radius.server, radius.user, radius.secret, radius.local_checkpin  |
        +---------+--------------------------------------------------------------------------------+
        | remote  | type=remote, remote.server, remote.local_checkpin, remote.serial               |
        +---------+--------------------------------------------------------------------------------+

        """

        ret = False
        response_detail = {}

        try:
            params = self.request_params.copy()
            params.setdefault("key_size", 20)

            # --------------------------------------------------------------- --

            # determine token class

            token_cls_alias = params.get("type") or "hmac"
            lower_alias = token_cls_alias.lower()

            if lower_alias not in tokenclass_registry:
                msg = f"admin/init failed: unknown token type {token_cls_alias!r}"
                raise TokenAdminError(
                    msg,
                    id=1610,
                )

            token_cls = tokenclass_registry.get(lower_alias)

            # --------------------------------------------------------------- --

            # call the token class hook in order to enrich/overwrite the
            # parameters

            helper_params = token_cls.get_helper_params_pre(params)
            params.update(helper_params)

            # --------------------------------------------------------------- --

            # check admin authorization
            user = request_context["RequestUser"]
            res = checkPolicyPre("admin", "init", params, user=user)

            # --------------------------------------------------------------- --

            # if no user is given, and the admin does not have permissions
            # on all realms, we set the tokens realm to the ones the admin has access to.
            # Otherwise the admin would not see the created token.
            tokenrealms = (
                res["realms"] if user.login == "" and "*" not in res["realms"] else []
            )
            if tokenrealms:
                log.debug("[init] setting tokenrealm %r", tokenrealms)

            # --------------------------------------------------------------- --

            helper_params = token_cls.get_helper_params_post(params, user=user)
            params.update(helper_params)

            # --------------------------------------------------------------- --

            serial = params.get("serial", None)
            prefix = params.get("prefix", None)

            # --------------------------------------------------------------- --

            th = TokenHandler()
            if not serial:
                serial = th.genSerial(token_cls_alias, prefix)
                params["serial"] = serial

            log.info(
                "[init] initialize token. user: %s, serial: %s",
                user.login,
                serial,
            )

            # --------------------------------------------------------------- --

            (ret, token) = th.initToken(params, user, tokenrealm=tokenrealms)

            # --------------------------------------------------------------- --

            # different token types return different information on
            # initialization (e.g. otpkey, pairing_url, etc)

            initDetail = token.getInitDetail(params, user)
            response_detail.update(initDetail)

            # --------------------------------------------------------------- --

            # prepare data for audit

            if token is not None and ret is True:
                g.audit["serial"] = token.getSerial()
                g.audit["token_type"] = token.type

            g.audit["success"] = ret
            g.audit["realm"] = user.realm or ", ".join(tokenrealms)
            g.reporting["realms"] = set(token.getRealms() or ["/:no realm:/"])
            # --------------------------------------------------------------- --

            checkPolicyPost("admin", "init", params, user=user)
            db.session.commit()

            # --------------------------------------------------------------- --

            # depending on parameters send back an qr image
            # or a text result

            if "qr" in params and token is not None:
                (rdata, hparam) = token.getQRImageData(response_detail)
                hparam.update(response_detail)
                hparam["qr"] = params.get("qr") or "html"
                return sendQRImageResult(rdata, hparam)
            else:
                return sendResult(ret, opt=response_detail)

        # ------------------------------------------------------------------- --

        except PolicyException as pe:
            log.error("[init] policy failed %r", pe)
            db.session.rollback()
            return sendError(pe, 1)

        except Exception as exx:
            log.error("[init] token initialization failed! %r", exx)
            db.session.rollback()
            return sendError(exx)

    ########################################################
    @methods(["POST"])
    def unassign(self):
        """

        unassigns a token from a user. i.e. the binding between the token
        and the user is removed


        :param serial:  (required) - the serial number / identifier of the token
        :param user:      (- )optional)

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """

        param = self.request_params

        try:
            try:
                serial = param["serial"]
            except KeyError as exx:
                msg = "Missing parameter: 'serial'"
                raise ParameterError(msg) from exx

            user = request_context["RequestUser"]

            # check admin authorization
            checkPolicyPre("admin", "unassign", param)

            th = TokenHandler()
            log.info(
                "[unassign] unassigning token with serial %r from user %r@%r",
                serial,
                user.login,
                user.realm,
            )
            g.audit["serial"] = serial
            token = get_token(serial)
            g.audit["token_type"] = token.type
            g.audit["user"] = token.getUsername()
            token_realms = token.getRealms()
            g.audit["realm"] = ", ".join(token_realms)
            g.reporting["realms"] = set(token_realms or ["/:no realm:/"])

            ret = th.unassignToken(serial, user, None)

            g.audit["success"] = ret

            opt_result_dict = {}
            if ret == 0 and serial:
                opt_result_dict["message"] = f"No token with serial {serial}"
            elif ret == 0 and user:
                opt_result_dict["message"] = "No tokens for this user"

            db.session.commit()
            return sendResult(ret, opt=opt_result_dict)

        except PolicyException as pe:
            log.error("[unassign] policy failed %r", pe)
            db.session.rollback()
            return sendError(pe, 1)

        except Exception as exx:
            log.error("[unassign] failed! %r", exx)
            db.session.rollback()
            return sendError(exx, 1)

    ########################################################
    @methods(["POST"])
    def assign(self):
        """

        assigns a token to a user, i.e. a binding between the token and
        the user is created.

        :param serial:      (required)  the serial number / identifier of the token
        :param user:        (required)  login user name
        :param pin:         (optional)  - the pin of the user pass

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """

        param = self.request_params

        try:
            upin = param.get("pin")

            user = request_context["RequestUser"]

            serials = param.get("serial", set())
            if isinstance(serials, str):
                serials = {serials}
            elif isinstance(serials, list):
                serials = set(serials)

            g.audit["serial"] = " ".join(serials)

            log.info("[assign] assigning token(s) with serial(s) %r", serials)

            call_params = {}
            call_params.update(param)

            res = True
            th = TokenHandler()
            realms = set()
            users = set()
            token_types = set()
            for serial in serials:
                # check admin authorization

                call_params["serial"] = serial
                checkPolicyPre("admin", "assign", call_params)

                # assignToken overwrites the token realms with the users realms
                # -> we need to trigger reporting for them.
                token = get_token(serial)
                token_source_realms = set(token.getRealms() or ["/:no realm:/"])

                # do the assignment
                res = res and th.assignToken(serial, user, upin, param=call_params)

                token = get_token(serial)
                token_realms = token.getRealms()
                realms.update(token_realms)
                users.add(token.getUsername())
                token_types.add(token.type)
                g.reporting["realms"] = set(
                    token_source_realms.union(token_realms or ["/:no realm:/"])
                )

            checkPolicyPost("admin", "assign", param, user)

            g.audit["success"] = res
            g.audit["token_type"] = ", ".join(token_types)
            g.audit["user"] = user.login or ", ".join(users)
            g.audit["realm"] = ", ".join(realms)

            db.session.commit()
            return sendResult(res, len(serials))

        except PolicyException as pe:
            log.error("[assign] policy failed %r", pe)
            db.session.rollback()
            return sendError(pe, 1)

        except Exception as exx:
            log.error("[assign] token assignment failed! %r", exx)
            db.session.rollback()
            return sendError(exx, 0)

    ########################################################
    @methods(["POST"])
    def setPin(self):
        """

        This function sets the userPin of tokens.
        The userpin is used to store the mOTP PIN of mOTP tokens
        or the OCRA PIN of OCRA tokens!
        !!! For setting the OTP PIN, use the function /admin/set!

        :param serial: (required) the token serial
        :param userpin: (required)  store the userpin

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """
        res = {}
        msg = "setting userPin failed"

        try:
            param = getLowerParams(self.request_params)

            try:
                serial = param["serial"]
                g.audit["serial"] = serial
            except KeyError as exx:
                msg = "Missing parameter: 'serial'"
                raise ParameterError(msg) from exx

            token = get_token(serial)
            if token.type not in ("mOTP", "ocra2"):
                msg = f"This type of pin cannot be set for a {token.type} token."
                raise Exception(msg)

            g.audit["token_type"] = token.type
            g.audit["user"] = token.getUsername()
            g.audit["realm"] = ", ".join(token.getRealms())

            try:
                userpin = param["userpin"]
                g.audit["userpin"] = userpin
            except KeyError as exx:
                msg = "Missing parameter: 'userpin'"
                raise ParameterError(msg) from exx

            # check admin authorization
            checkPolicyPre("admin", "setPin", param)

            log.info("[setPin] setting userPin for token with serial %s", serial)
            ret = setPinUser(userpin, serial)
            res["set userpin"] = ret

            g.audit["action_detail"] += "userpin, "
            g.audit["success"] = bool(ret)
            token = get_token(serial)
            g.audit["token_type"] = token.type
            g.audit["user"] = token.getUsername()
            g.audit["realm"] = ", ".join(token.getRealms())

            db.session.commit()
            return sendResult(res, 1)

        except PolicyException as pex:
            log.error("[setPin] policy failed %r, %r", msg, pex)
            db.session.rollback()
            return sendError(pex, 1)

        except Exception as exx:
            log.error("[setPin] %s :%r", msg, exx)
            db.session.rollback()
            return sendError(exx, 0)

    @methods(["POST"])
    def setValidity(self):
        """
        dedicated backend for setting the token validity for
        multiple selected tokens.

        :param tokens[]: the token serials (required)
        :param countAuthSuccessMax:
            the maximum number of allowed successful authentications
        :param countAuthMax:
            the maximum number of allowed successful authentications
        :param validityPeriodStart: utc - unix seconds as int

        :param validityPeriodEnd: utc - unix seconds as int

        .. note::

            the parameter names are the same as with the admin/set
            while admin/set does not support multiple tokens

        .. note::

            if the value is 'unlimited' the validity limit will be removed

        :return: json document with the value field containing the serials of
          the modified tokens

        :raises Exception:
            if an error occurs an exception is serialized and returned
        """
        try:
            g.audit["info"] = "set token validity"

            param = getLowerParams(self.request_params)

            # -------------------------------------------------------------- --

            # check admin authorization

            admin_user = getUserFromRequest()

            checkPolicyPre("admin", "set", param, user=admin_user)

            # -------------------------------------------------------------- --

            # process the arguments

            unlimited = "unlimited"

            countAuthSuccessMax = None
            if "countAuthSuccessMax".lower() in param:
                countAuthSuccessMax = param.get("countAuthSuccessMax".lower())

            countAuthMax = None
            if "countAuthMax".lower() in param:
                countAuthMax = param.get("countAuthMax".lower())

            validityPeriodStart = None
            if "validityPeriodStart".lower() in param:
                validityPeriodStart = param.get("validityPeriodStart".lower())

            validityPeriodEnd = None
            if "validityPeriodEnd".lower() in param:
                validityPeriodEnd = param.get("validityPeriodEnd".lower())

            # -------------------------------------------------------------- --

            try:
                serials = self.request_params["tokens"]
                g.audit["serial"] = " ".join(serials)
            except KeyError as exx:
                msg = "missing parameter: tokens[]"
                raise ParameterError(msg) from exx

            tokens = [
                token for serial in serials for token in get_tokens(serial=serial)
            ]

            # -------------------------------------------------------------- --

            # push the validity values into the tokens

            users = set()
            realms = set()
            token_types = set()

            for token in tokens:
                # ---------------------------------------------------------- --

                if countAuthMax == unlimited:
                    token.del_count_auth_max()

                elif countAuthMax is not None:
                    token.count_auth_max = int(countAuthMax)

                # ---------------------------------------------------------- --

                if countAuthSuccessMax == unlimited:
                    token.del_count_auth_success_max()

                elif countAuthSuccessMax is not None:
                    token.count_auth_success_max = int(countAuthSuccessMax)

                # ---------------------------------------------------------- --

                if validityPeriodStart == unlimited:
                    token.del_validity_period_start()

                elif validityPeriodStart is not None:
                    validity_period_start = (
                        datetime.utcfromtimestamp(int(validityPeriodStart))
                        .strftime("%d/%m/%y %H:%M")
                        .strip()
                    )
                    token.validity_period_start = validity_period_start

                # ---------------------------------------------------------- --

                if validityPeriodEnd == unlimited:
                    token.del_validity_period_end()

                elif validityPeriodEnd is not None:
                    validity_period_end = (
                        datetime.utcfromtimestamp(int(validityPeriodEnd))
                        .strftime("%d/%m/%y %H:%M")
                        .strip()
                    )

                    token.validity_period_end = validity_period_end

                realms.update(token.getRealms())
                users.add(token.getUsername())
                token_types.add(token.type)

            g.audit["success"] = 1
            g.audit["token_type"] = ", ".join(token_types)
            g.audit["user"] = ", ".join(users)
            g.audit["realm"] = ", ".join(realms)
            g.audit["action_detail"] = (f"{serials!r} ")[:80]

            db.session.commit()
            return sendResult(serials, 1)

        except PolicyException as pex:
            log.error("policy failed%r", pex)
            db.session.rollback()
            return sendError(pex, 1)

        except Exception as exx:
            g.audit["success"] = False

            log.error("%r", exx)
            db.session.rollback()
            return sendError(exx, 0)

    ########################################################
    @methods(["POST"])
    def set(self):
        """

        this function is used to set many different values of a token.

        :param serial:      (optional)
        :param user:        (optional)
        :param pin:         (optional)  - set the OTP PIN
        :param MaxFailCount:   (optional)  - set the maximum fail counter of a token
        :param SyncWindow:     (optional)  - set the synchronization window of the token
        :param OtpLen:         (optional)  - set the OTP Lenght of the token
        :param CounterWindow:  (optional)  - set the counter window (blank presses)
        :param hashlib:        (optional)  - set the hashing algo for HMAC tokens. This can be sha1, sha256, sha512
        :param timeWindow:     (optional)  - set the synchronize window for timebased tokens (in seconds)
        :param timeStep:       (optional)  - set the timestep for timebased tokens (usually 30 or 60 seconds)
        :param timeShift:      (optional)  - set the shift or timedrift of this token
        :param countAuthSuccessMax:     (optional)     - set the maximum allowed successful authentications
        :param countAuthSuccess:        (optional)     - set the counter of the successful authentications
        :param countAuth:         (optional)  - set the counter of authentications
        :param countAuthMax:      (optional)  - set the maximum allowed authentication tries
        :param validityPeriodStart:     (optional)  - set the start date of the validity period. The token can not be used before this date
        :param validityPeriodEnd:       (optional)  - set the end date of the validaity period. The token can not be used after this date
        :param phone: set the phone number for an SMS token

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """
        res = {}
        count = 0

        description = "set: parameters are\
        pin\
        MaxFailCount\
        SyncWindow\
        OtpLen\
        CounterWindow\
        hashlib\
        timeWindow\
        timeStep\
        timeShift\
        countAuthSuccessMax\
        countAuthSuccess\
        countAuth\
        countAuthMax\
        validityPeriodStart\
        validityPeriodEnd\
        description\
        phone\
        "
        msg = ""

        try:
            param = getLowerParams(self.request_params)

            serial = param.get("serial")
            g.audit["serial"] = serial

            # check admin authorization
            user = request_context["RequestUser"]
            checkPolicyPre("admin", "set", param, user=user)

            th = TokenHandler()
            tokens_user_serial = []
            # # if there is a pin
            if "pin" in param:
                msg = "[set] setting pin failed"
                upin = param["pin"]
                log.info("[set] setting pin for token with serial %r", serial)
                if getOTPPINEncrypt(serial=serial, user=user) == 1:
                    param["encryptpin"] = "True"
                ret = setPin(upin, user, serial, param)
                res["set pin"] = ret
                count = count + 1
                g.audit["action_detail"] += "pin, "

            if "MaxFailCount".lower() in param:
                msg = "[set] setting MaxFailCount failed"
                maxFail = int(param["MaxFailCount".lower()])
                log.info(
                    "[set] setting maxFailCount (%r) for token with serial %r",
                    maxFail,
                    serial,
                )
                ret = th.setMaxFailCount(maxFail, user, serial)
                res["set MaxFailCount"] = ret
                count = count + 1
                g.audit["action_detail"] += f"maxFailCount={maxFail}, "

            if "SyncWindow".lower() in param:
                msg = "[set] setting SyncWindow failed"
                syncWindow = int(param["SyncWindow".lower()])
                log.info(
                    "[set] setting syncWindow (%r) for token with serial %r",
                    syncWindow,
                    serial,
                )
                ret = th.setSyncWindow(syncWindow, user, serial)
                res["set SyncWindow"] = ret
                count = count + 1
                g.audit["action_detail"] += f"syncWindow={syncWindow}, "

            if "description".lower() in param:
                msg = "[set] setting description failed"
                description = param["description".lower()]
                log.info(
                    "[set] setting description (%r) for token with serial %r",
                    description,
                    serial,
                )
                ret = th.setDescription(description, user, serial)
                res["set description"] = ret
                count = count + 1
                g.audit["action_detail"] += f"description={description!r}, "

            if "CounterWindow".lower() in param:
                msg = "[set] setting CounterWindow failed"
                counterWindow = int(param["CounterWindow".lower()])
                log.info(
                    "[set] setting counterWindow (%r) for token with serial %r",
                    counterWindow,
                    serial,
                )
                ret = th.setCounterWindow(counterWindow, user, serial)
                res["set CounterWindow"] = ret
                count = count + 1
                g.audit["action_detail"] += f"counterWindow={counterWindow}, "

            if "OtpLen".lower() in param:
                msg = "[set] setting OtpLen failed"
                otpLen = int(param["OtpLen".lower()])
                log.info(
                    "[set] setting OtpLen (%r) for token with serial %r",
                    otpLen,
                    serial,
                )
                ret = th.setOtpLen(otpLen, user, serial)
                res["set OtpLen"] = ret
                count = count + 1
                g.audit["action_detail"] += f"otpLen={otpLen}, "

            if "hashlib".lower() in param:
                msg = "[set] setting hashlib failed"
                hashlib = param["hashlib".lower()]
                log.info(
                    "[set] setting hashlib (%r) for token with serial %r",
                    hashlib,
                    serial,
                )
                th = TokenHandler()
                ret = th.setHashLib(hashlib, user, serial)
                res["set hashlib"] = ret
                count = count + 1
                g.audit["action_detail"] += f"hashlib={hashlib!s}, "

            if "timeWindow".lower() in param:
                msg = "[set] setting timeWindow failed"
                timeWindow = int(param["timeWindow".lower()])
                log.info(
                    "[set] setting timeWindow (%r) for token with serial %r",
                    timeWindow,
                    serial,
                )
                ret = th.addTokenInfo("timeWindow", timeWindow, user, serial)
                res["set timeWindow"] = ret
                count = count + 1
                g.audit["action_detail"] += f"timeWindow={timeWindow}, "

            if "timeStep".lower() in param:
                msg = "[set] setting timeStep failed"
                timeStep = int(param["timeStep".lower()])
                log.info(
                    "[set] setting timeStep (%r) for token with serial %r",
                    timeStep,
                    serial,
                )
                token = get_token(serial)
                token.timeStep = timeStep

                res["set timeStep"] = 1
                count = count + 1
                g.audit["action_detail"] += f"timeStep={timeStep}, "

            if "timeShift".lower() in param:
                msg = "[set] setting timeShift failed"
                timeShift = int(param["timeShift".lower()])
                log.info(
                    "[set] setting timeShift (%r) for token with serial %r",
                    timeShift,
                    serial,
                )
                ret = th.addTokenInfo("timeShift", timeShift, user, serial)
                res["set timeShift"] = ret
                count = count + 1
                g.audit["action_detail"] += f"timeShift={timeShift}, "

            if "countAuth".lower() in param:
                msg = "[set] setting countAuth failed"
                ca = int(param["countAuth".lower()])
                log.info(
                    "[set] setting count_auth (%r) for token with serial %r",
                    ca,
                    serial,
                )
                tokens = (
                    tokens_user_serial
                    if tokens_user_serial
                    else get_tokens(user, serial)
                )
                [setattr(token, "count_auth", ca) for token in tokens]
                count += len(tokens)
                res["set countAuth"] = len(tokens)
                g.audit["action_detail"] += f"countAuth={ca}, "

            if "countAuthMax".lower() in param:
                msg = "[set] setting countAuthMax failed"
                ca = int(param["countAuthMax".lower()])
                log.info(
                    "[set] setting count_auth_max (%r) for token with serial %r",
                    ca,
                    serial,
                )
                tokens = (
                    tokens_user_serial
                    if tokens_user_serial
                    else get_tokens(user, serial)
                )
                [setattr(tok, "count_auth_max", ca) for tok in tokens]
                count += len(tokens)
                res["set countAuthMax"] = len(tokens)
                g.audit["action_detail"] += f"countAuthMax={ca}, "

            if "countAuthSuccess".lower() in param:
                msg = "[set] setting countAuthSuccess failed"
                ca = int(param["countAuthSuccess".lower()])
                log.info(
                    "[set] setting count_auth_success (%r) for token withserial %r",
                    ca,
                    serial,
                )
                tokens = (
                    tokens_user_serial
                    if tokens_user_serial
                    else get_tokens(user, serial)
                )
                [setattr(tok, "count_auth_success", ca) for tok in tokens]
                count += len(tokens)
                res["set countAuthSuccess"] = len(tokens)
                g.audit["action_detail"] += f"countAuthSuccess={ca}, "

            if "countAuthSuccessMax".lower() in param:
                msg = "[set] setting countAuthSuccessMax failed"
                ca = int(param["countAuthSuccessMax".lower()])
                log.info(
                    "[set] setting count_auth_success_max (%r) for token withserial %r",
                    ca,
                    serial,
                )
                tokens = (
                    tokens_user_serial
                    if tokens_user_serial
                    else get_tokens(user, serial)
                )
                [setattr(tok, "count_auth_success_max", ca) for tok in tokens]
                count += len(tokens)
                res["set countAuthSuccessMax"] = len(tokens)
                g.audit["action_detail"] += f"countAuthSuccessMax={ca}, "

            if "validityPeriodStart".lower() in param:
                msg = "[set] setting validityPeriodStart failed"
                ca = param["validityPeriodStart".lower()]
                log.info(
                    "[set] setting validity_period_start (%r) for token withserial %r",
                    ca,
                    serial,
                )
                tokens = (
                    tokens_user_serial
                    if tokens_user_serial
                    else get_tokens(user, serial)
                )
                [setattr(tok, "validity_period_start", ca) for tok in tokens]
                count += len(tokens)
                res["set validityPeriodStart"] = len(tokens)
                g.audit["action_detail"] += f"validityPeriodStart={ca!s}, "

            if "validityPeriodEnd".lower() in param:
                msg = "[set] setting validityPeriodEnd failed"
                ca = param["validityPeriodEnd".lower()]
                log.info(
                    "[set] setting validity_period_end (%r) for token withserial %r",
                    ca,
                    serial,
                )
                tokens = (
                    tokens_user_serial
                    if tokens_user_serial
                    else get_tokens(user, serial)
                )
                [setattr(tok, "validity_period_end", ca) for tok in tokens]
                count += len(tokens)
                res["set validityPeriodEnd"] = len(tokens)
                g.audit["action_detail"] += f"validityPeriodEnd={ca!s}, "

            if "phone" in param:
                msg = "[set] setting phone failed"
                ca = param["phone".lower()]
                log.info(
                    "[set] setting phone (%r) for token with serial %r",
                    ca,
                    serial,
                )
                tokens = (
                    tokens_user_serial
                    if tokens_user_serial
                    else get_tokens(user, serial)
                )
                for tok in tokens:
                    tok.addToTokenInfo("phone", ca)
                count += len(tokens)
                res["set phone"] = len(tokens)
                g.audit["action_detail"] += f"phone={ca!s}, "

            if count == 0:
                db.session.rollback()
                return sendError(ParameterError(f"Usage: {description}", id=77))

            # TODO
            # Handle multiple tokens
            # e.g serials = " ".join([t.token.LinOtpTokenSerialnumber for t in tokens])
            g.audit["success"] = count
            tokens = get_tokens(user, serial=serial)
            g.audit["serial"] = (
                serial
                if serial
                else " ".join([t.token.LinOtpTokenSerialnumber for t in tokens])
            )
            g.audit["token_type"] = ", ".join([t.type for t in tokens])
            g.audit["user"] = user.login or ", ".join([t.getUsername() for t in tokens])
            realms = (
                [user.realm]
                if user.realm != ""
                else [realm for t in tokens for realm in t.getRealms()]
            )
            g.audit["realm"] = ", ".join(realms)

            db.session.commit()
            return sendResult(res, 1)

        except PolicyException as pe:
            log.error("[set] policy failed: %s, %r", msg, pe)
            db.session.rollback()
            return sendError(pe, 1)

        except Exception as exx:
            log.error("%s: %r", msg, exx)
            db.session.rollback()
            # as this message is directly returned into the javascript
            # alert as escaped string we remove here all escaping chars
            error = f"{exx!r}"
            error = error.replace('"', "|")
            error = error.replace("'", ":")
            error = error.replace("&", "+")
            error = error.replace(">", "]")
            error = error.replace("<", "[")
            result = f"{msg}: {error}"
            return sendError(result)

    ########################################################
    @methods(["POST"])
    def resync(self):
        """
        this function resync the token, if the counter on server side is out of sync
        with the physical token.

        :param serial:  serial or user (required)
        :param user: s.o.
        :param otp1: the next otp to be found
        :param otp2: the next otp after the otp1

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """

        param = self.request_params
        try:
            serial = param.get("serial")
            g.audit["serial"] = serial
            user = request_context["RequestUser"]

            try:
                otp1 = param["otp1"]
            except KeyError as exx:
                msg = "Missing parameter: 'otp1'"
                raise ParameterError(msg) from exx

            try:
                otp2 = param["otp2"]
            except KeyError as exx:
                msg = "Missing parameter: 'otp2'"
                raise ParameterError(msg) from exx

            # to support the challenge based resync, we have to pass the challenges
            #    down to the token implementation

            chall1 = param.get("challenge1")
            chall2 = param.get("challenge2")

            options = None
            if chall1 is not None and chall2 is not None:
                options = {"challenge1": chall1, "challenge2": chall2}

            # check admin authorization
            checkPolicyPre("admin", "resync", param)
            th = TokenHandler()
            log.info(
                "[resync] resyncing token with serial %r, user %r@%r",
                serial,
                user.login,
                user.realm,
            )
            res = th.resyncToken(otp1, otp2, user, serial, options)

            g.audit["success"] = res
            tokens = get_tokens(user, serial=serial)
            g.audit["serial"] = (
                serial
                if serial
                else " ".join([t.token.LinOtpTokenSerialnumber for t in tokens])
            )
            g.audit["token_type"] = ", ".join([t.type for t in tokens])
            g.audit["user"] = user.login or ", ".join([t.getUsername() for t in tokens])
            realms = (
                [user.realm]
                if user.realm != ""
                else [realm for t in tokens for realm in t.getRealms()]
            )
            g.audit["realm"] = ", ".join(realms)

            db.session.commit()
            return sendResult(res, 1)

        except PolicyException as pe:
            log.error("[resync] policy failed %r", pe)
            db.session.rollback()
            return sendError(pe, 1)

        except Exception as exx:
            log.error("[resync] resyncing token failed %r", exx)
            db.session.rollback()
            return sendError(exx, 1)

    ########################################################
    @deprecated_methods(["POST"])
    def userlist(self):
        """
        lists the user in a realm

        :param <searchexpr>: will be retrieved from the UserIdResolverClass
        :param realm: a realm, which is a collection of resolver configurations
        :param resConf: a destinct resolver configuration
        :param page: the number of page, which should be retrieved (optional)
        :param rp: the number of users per page (optional)

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """

        param = self.request_params.copy()

        # check admin authorization
        # check if we got a realm or resolver, that is ok!
        try:
            # TODO:
            # check if admin is allowed to see the useridresolvers
            # as users_iters is (user_iterator, resolvername)
            # we could simply check if the admin is allowed to view the
            # resolver
            # hint:
            # done by getting the list of realm the admin is allowed to view
            # and add this as paramter list to the getUserListIterators

            realm = param.get("realm")
            g.audit["realm"] = realm

            # Here we need to list the users, that are only visible in the
            # realm!! we could also only list the users in the realm, if the
            # admin got the right "userlist".

            checkPolicyPre("admin", "userlist", param)

            filter_fields = 0
            user = request_context["RequestUser"]

            log.info("[userlist] displaying users with param: %s, ", param)

            if len(user.realm) > 0:
                filter_fields += 1
            if len(user.resolver_config_identifier) > 0:
                filter_fields += 1

            if len(param) < filter_fields:
                usage = {
                    "usage": "list available users matching the given search patterns:"
                }
                usage["searchfields"] = getSearchFields(user)
                res = usage
                db.session.commit()
                return sendResult(res)

            list_params = {}
            list_params.update(param)

            rp = None
            if "rp" in list_params:
                rp = int(list_params["rp"])
                del list_params["rp"]

            page = None
            if "page" in list_params:
                page = list_params["page"]
                del list_params["page"]

            users_iters = getUserListIterators(list_params, user)

            g.audit["success"] = True
            g.audit["realm"] = realm
            g.audit["info"] = f"realm: {realm}"

            db.session.commit()

            return Response(
                stream_with_context(
                    sendResultIterator(iterate_users(users_iters), rp=rp, page=page)
                ),
                mimetype="application/json",
            )

            # ---------------------------------------------------------- --

        except PolicyException as pe:
            log.error("[userlist] policy failed %r", pe)
            db.session.rollback()
            return sendError(pe, 1)

        except Exception as exx:
            log.error("[userlist] failed %r", exx)
            db.session.rollback()
            return sendError(exx)

    ########################################################
    @methods(["POST"])
    def tokenrealm(self):
        """
        set the realms a token belongs to

        :param serial:     (required)   serial number of the token
        :param realms:     (required)   comma seperated list of realms

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned
        """

        param = self.request_params
        try:
            try:
                serial = param["serial"]
                g.audit["serial"] = serial
            except KeyError as exx:
                msg = "Missing parameter: 'serial'"
                raise ParameterError(msg) from exx

            try:
                realms = param["realms"]
            except KeyError as exx:
                msg = "Missing parameter: 'realms'"
                raise ParameterError(msg) from exx
            realmList = list({r.strip() for r in realms.split(",")})
            g.audit["realm"] = ", ".join(realmList)

            # check admin authorization
            checkPolicyPre("admin", "tokenrealm", param)

            source_realms = set(getTokenRealms(serial) or ["/:no realm:/"])
            log.info(
                "[tokenrealm] setting realms for token %s to %s",
                serial,
                realms,
            )
            ret = setRealms(serial, realmList)

            g.audit["success"] = ret
            g.audit["serial"] = serial
            token = get_token(serial)
            g.audit["token_type"] = token.type
            g.audit["user"] = token.getUsername()
            g.audit["info"] = (
                f"From {','.join(source_realms)} to {','.join(realmList or ['/:no realm:/'])}"
            )
            g.reporting["realms"] = source_realms.union(
                {realm if realm else "/:no realm:/" for realm in realmList}
            )

            db.session.commit()
            return sendResult(ret, 1)

        except PolicyException as pe:
            log.error("[tokenrealm] policy failed %r", pe)
            db.session.rollback()
            return sendError(pe, 1)

        except Exception as exx:
            log.error("[tokenrealm] error setting realms for token %r", exx)
            db.session.rollback()
            return sendError(exx, 1)

    ########################################################
    @methods(["POST"])
    def reset(self):
        """
        reset the FailCounter of a Token

        :param user or serial: to identify the tokens

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """

        param = self.request_params

        serial = param.get("serial")
        g.audit["serial"] = serial
        user = request_context["RequestUser"]

        try:
            # check admin authorization
            checkPolicyPre("admin", "reset", param, user=user)

            log.info(
                "[reset] resetting the FailCounter for token with serial %s",
                serial,
            )
            ret = resetToken(user, serial)

            g.audit["success"] = ret
            tokens = get_tokens(user, serial=serial)
            g.audit["serial"] = (
                serial
                if serial
                else " ".join([t.token.LinOtpTokenSerialnumber for t in tokens])
            )
            g.audit["token_type"] = ", ".join([t.type for t in tokens])
            g.audit["user"] = user.login or ", ".join([t.getUsername() for t in tokens])
            realms = (
                [user.realm]
                if user.realm != ""
                else [realm for t in tokens for realm in t.getRealms()]
            )
            g.audit["realm"] = ", ".join(realms)

            # DeleteMe: This code will never run, since getUserFromParam
            # always returns a realm!
            # if "" == g.audit['realm'] and "" != g.audit['user']:
            #    g.audit['realm'] = getDefaultRealm()

            opt_result_dict = {}
            if ret == 0 and serial:
                opt_result_dict["message"] = f"No token with serial {serial}"
            elif ret == 0 and user:
                opt_result_dict["message"] = "No tokens for this user"

            db.session.commit()
            return sendResult(ret, opt=opt_result_dict)

        except PolicyException as pe:
            log.error("[reset] policy failed %r", pe)
            db.session.rollback()
            return sendError(pe, 1)

        except Exception as exx:
            log.error("[reset] Error resetting failcounter %r", exx)
            db.session.rollback()
            return sendError(exx)

    ########################################################
    @methods(["POST"])
    def copyTokenPin(self):
        """
        copies the token pin from one token to another

        :param from:  (required)  serial of token from
        :param to:    (required)  serial of token to

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """
        ret = 0
        err_string = ""
        param = self.request_params

        try:
            try:
                serial_from = param["from"]
            except KeyError as exx:
                msg = "Missing parameter: 'from'"
                raise ParameterError(msg) from exx

            try:
                serial_to = param["to"]
                g.audit["serial"] = serial_to
            except KeyError as exx:
                msg = "Missing parameter: 'to'"
                raise ParameterError(msg) from exx

            # check admin authorization
            checkPolicyPre("admin", "copytokenpin", param)

            th = TokenHandler()
            log.info(
                "[copyTokenPin] copying Pin from token %s to token %s",
                serial_from,
                serial_to,
            )
            ret = th.copyTokenPin(serial_from, serial_to)

            g.audit["success"] = 1 if ret == 1 else 0
            g.audit["serial"] = serial_to
            token = get_token(serial_to)
            g.audit["token_type"] = token.type
            g.audit["user"] = token.getUsername()
            g.audit["realm"] = ", ".join(token.getRealms())
            g.audit["action_detail"] = f"from {serial_from}"

            err_string = str(ret)
            if ret == -1:
                err_string = "can not get PIN from source token"
            elif ret == -2:
                err_string = "can not set PIN to destination token"
            if ret != 1:
                g.audit["action_detail"] += ", " + err_string

            db.session.commit()
            # Success
            if ret == 1:
                return sendResult(True)
            else:
                return sendError(f"copying token pin failed: {err_string}")

        except PolicyException as pe:
            log.error("[losttoken] Error doing losttoken %r", pe)
            db.session.rollback()
            return sendError(pe, 1)

        except Exception as exx:
            log.error("[copyTokenPin] Error copying token pin: %r", exx)
            db.session.rollback()
            return sendError(exx)

    ########################################################
    @methods(["POST"])
    def copyTokenUser(self):
        """
        copies the token user from one token to another

        :param from:  (required)  serial of token from
        :param to:    (required)  serial of token to

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned


        """
        ret = 0
        err_string = ""
        param = self.request_params

        try:
            try:
                serial_from = param["from"]
            except KeyError as exx:
                msg = "Missing parameter: 'from'"
                raise ParameterError(msg) from exx

            try:
                serial_to = param["to"]
                g.audit["serial"] = serial_to
            except KeyError as exx:
                msg = "Missing parameter: 'to'"
                raise ParameterError(msg) from exx

            # check admin authorization
            checkPolicyPre("admin", "copytokenuser", param)

            th = TokenHandler()
            log.info(
                "[copyTokenUser] copying User from token %s to token %s",
                serial_from,
                serial_to,
            )
            ret = th.copyTokenUser(serial_from, serial_to)

            g.audit["success"] = ret
            token = get_token(serial_to)
            token_realms = token.getRealms()
            g.audit["token_type"] = token.type
            g.audit["user"] = token.getUsername()
            g.audit["realm"] = ", ".join(token_realms)
            g.audit["action_detail"] = f"from {serial_from}"
            g.reporting["realms"] = set(token_realms or ["/:no realms"])

            err_string = str(ret)
            if ret == -1:
                err_string = "can not get user from source token"
            if ret == -2:
                err_string = "can not set user to destination token"
            if ret != 1:
                g.audit["action_detail"] += ", " + err_string
                g.audit["success"] = 0

            db.session.commit()
            # Success
            if ret == 1:
                return sendResult(True)
            else:
                return sendError(f"copying token user failed: {err_string}")

        except PolicyException as pe:
            log.error("[copyTokenUser] Policy Exception %r", pe)
            db.session.rollback()
            return sendError(pe, 1)

        except Exception as exx:
            log.error("[copyTokenUser] Error copying token user: %r", exx)
            db.session.rollback()
            return sendError(exx)

    ########################################################
    @methods(["POST"])
    def losttoken(self):
        """
        creates a new password token and copies the PIN and the
        user of the old token to the new token.
        The old token is disabled.

        :param serial: serial of the old token
        :param type:    (optional) , password, email or sms
        :param email:   (optional) , email address, to overrule the owner email
        :param mobile:  (optional) , mobile number, to overrule the owner mobile

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """
        res = {}
        param = self.request_params.copy()

        try:
            serial = param["serial"]
            g.audit["serial"] = serial

            # check admin authorization
            checkPolicyPre("admin", "losttoken", param)

            th = TokenHandler()
            res = th.losttoken(serial, param=param)
            g.audit["success"] = 1 if res else 0

            new_serial = res.get("serial")
            g.audit["serial"] = new_serial
            token = get_token(new_serial)
            token_realms = token.getRealms()
            g.audit["token_type"] = token.type
            g.audit["user"] = token.getUsername()
            g.audit["realm"] = ", ".join(token_realms)
            g.audit["action_detail"] = f"from {serial}"
            g.reporting["realms"] = set(
                (token_realms or ["/:no realm:/"])
                + (getTokenRealms(serial) or ["/:no realm:/"])
            )

            db.session.commit()
            return sendResult(res)

        except PolicyException as pe:
            log.error("[losttoken] Policy Exception: %r", pe)
            db.session.rollback()
            return sendError(pe, 1)

        except Exception as exx:
            log.error("[losttoken] Error doing losttoken %r", exx)
            db.session.rollback()
            return sendError(exx)

    ########################################################
    @methods(["POST"])
    def loadtokens(self):
        """
        loads a whole token file to the server

        :param file:  the file in a post request
        :param type:  the file type.
        :param realm: the target real of the tokens

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned


        """
        res = "Loading token file failed!"
        known_types = ["aladdin-xml", "oathcsv", "yubikeycsv"]
        TOKENS = {}
        res = None

        sendResultMethod = sendResult
        sendErrorMethod = sendError

        from linotp.lib.ImportOTP import getKnownTypes  # noqa: PLC0415

        known_types.extend(getKnownTypes())
        log.info(
            "[loadtokens] importing linotp.lib. Known import types: %s",
            known_types,
        )

        from linotp.lib.ImportOTP.PSKC import parsePSKCdata  # noqa: PLC0415

        log.info("[loadtokens] loaded parsePSKCdata")

        from linotp.lib.ImportOTP.DPWplain import parseDPWdata  # noqa: PLC0415

        log.info("[loadtokens] loaded parseDPWdata")

        from linotp.lib.ImportOTP.eTokenDat import parse_dat_data  # noqa: PLC0415

        log.info("[loadtokens] loaded parseDATdata")

        params = self.request_params

        try:
            log.debug("[loadtokens] getting upload data")
            log.debug("[loadtokens] %r", request.args)
            tokenFile = request.files["file"]
            fileType = params["type"]
            targetRealm = params.get("realm", params.get("targetrealm", "")).lower()

            # for encrypted token import data, this is the decryption key
            transportkey = params.get("transportkey", None)
            if not transportkey:
                transportkey = None

            pskc_type = None
            pskc_password = None
            pskc_preshared = None
            pskc_checkserial = False

            hashlib = None

            if fileType == "pskc":
                pskc_type = params["pskc_type"]
                pskc_password = params["pskc_password"]
                pskc_preshared = params["pskc_preshared"]
                if "pskc_checkserial" in params:
                    pskc_checkserial = True

            fileString = ""
            typeString = ""

            log.debug(
                "[loadtokens] loading token file to server Filetype: %s. File: %s",
                fileType,
                tokenFile,
            )

            # In case of form post requests, it is a "instance" of FileStorage
            # i.e. the Filename is selected in the browser and the data is
            # transferred in an iframe. see:
            # http://jquery.malsup.com/form/#sample4

            if isinstance(tokenFile, FileStorage):
                log.debug("[loadtokens] Field storage file: %s", tokenFile)
                fileString = tokenFile.read().decode()
                sendResultMethod = sendXMLResult
                sendErrorMethod = sendXMLError
            else:
                fileString = tokenFile
            log.debug("[loadtokens] fileString: %s", fileString)

            if isinstance(fileType, FileStorage):
                log.debug("[loadtokens] Field storage type: %s", fileType)
                typeString = fileType.read()
            else:
                typeString = fileType
            log.debug("[loadtokens] typeString: <<%s>>", typeString)
            if typeString == "pskc":
                log.debug(
                    "[loadtokens] passing password: %s, key: %s, checkserial: %s",
                    pskc_password,
                    pskc_preshared,
                    pskc_checkserial,
                )

            if fileString == "" or typeString == "":
                log.error("[loadtokens] file: %s", fileString)
                log.error("[loadtokens] type: %s", typeString)
                log.error(
                    "[loadtokens] Error loading/importing token file. "
                    "file or type empty!"
                )
                return sendErrorMethod("Error loading tokens. File or Type empty!")

            if typeString not in known_types:
                log.error(
                    "[loadtokens] Unknown file type: >>%s<<. "
                    "We only know the types: %s",
                    typeString,
                    ", ".join(known_types),
                )
                return sendErrorMethod(
                    (
                        "Unknown file type: >>{}<<. We only know the types: {}".format(
                            typeString, ", ".join(known_types)
                        )
                    ),
                )

            # Parse the tokens from file and get dictionary
            if typeString == "aladdin-xml":
                TOKENS = parseSafeNetXML(fileString)
                # we only do hashlib for aladdin at the moment.
                if "aladdin_hashlib" in params:
                    hashlib = params["aladdin_hashlib"]

            elif typeString == "oathcsv":
                TOKENS = parseOATHcsv(fileString)

            elif typeString == "yubikeycsv":
                TOKENS = parseYubicoCSV(fileString)

            elif typeString == "dpw":
                TOKENS = parseDPWdata(fileString)

            elif typeString == "dat":
                startdate = params.get("startdate", None)
                TOKENS = parse_dat_data(fileString, startdate)

            elif typeString == "feitian":
                TOKENS = parsePSKCdata(fileString, do_feitian=True)

            elif typeString == "pskc":
                if pskc_type == "key":
                    TOKENS = parsePSKCdata(
                        fileString,
                        preshared_key_hex=pskc_preshared,
                        do_checkserial=pskc_checkserial,
                    )

                elif pskc_type == "password":
                    TOKENS = parsePSKCdata(
                        fileString,
                        password=pskc_password,
                        do_checkserial=pskc_checkserial,
                    )

                elif pskc_type == "plain":
                    TOKENS = parsePSKCdata(fileString, do_checkserial=pskc_checkserial)

            tokenrealm = ""

            # -------------------------------------------------------------- --
            # first check if we are allowed to import the tokens at all
            # if not, this will raise a PolicyException

            rights = checkPolicyPre("admin", "import", {})

            # if an empty list of realms is returned, there is no admin policy
            # defined at all. So we grant access to all realms

            access_realms = rights.get("realms")
            if access_realms == []:
                access_realms = ["*"]

            # -------------------------------------------------------------- --

            # determin the admin realms

            available_realms = getRealms()

            if "*" in access_realms:
                admin_realms = available_realms

            else:
                # remove non existing realms from the admin realms

                admin_realms = list(set(available_realms) & set(access_realms))

                # this is a ugly unlogical case for legacy compliance

                if admin_realms:
                    tokenrealm = admin_realms[0]

            # -------------------------------------------------------------- --

            # determin the target tokenrealm

            if targetRealm:
                if targetRealm not in admin_realms:
                    msg = "target realm could not be assigned"
                    raise Exception(msg)

                tokenrealm = targetRealm

                # double check, if this is an allowed targetrealm

                checkPolicyPre("admin", "loadtokens", {"tokenrealm": tokenrealm})

            log.info("[loadtokens] setting tokenrealm %r", tokenrealm)

            # -------------------------------------------------------------- --

            # Now import the Tokens from the dictionary

            log.debug("[loadtokens] read %i tokens. starting import now", len(TOKENS))

            ret = ""
            th = TokenHandler()
            for serial, token in TOKENS.items():
                log.debug("[loadtokens] importing token %s", token)

                log.info(
                    "[loadtokens] initialize token. serial: %r, realm: %r",
                    serial,
                    tokenrealm,
                )

                # for the eToken dat we assume, that it brings all its
                # init parameters in correct format

                if typeString == "dat":
                    init_param = token

                else:
                    init_param = {
                        "serial": serial,
                        "type": token["type"],
                        "description": token.get("description", "imported"),
                        "otpkey": token["hmac_key"],
                        "otplen": token.get("otplen"),
                        "timeStep": token.get("timeStep"),
                        "hashlib": token.get("hashlib"),
                    }

                # add ocrasuite for ocra tokens, only if ocrasuite is not empty
                if token["type"] in ["ocra2"] and token.get("ocrasuite", "") != "":
                    init_param["ocrasuite"] = token.get("ocrasuite")

                if hashlib and hashlib != "auto":
                    init_param["hashlib"] = hashlib

                init_param["enable"] = boolean(params.get("enable", True))

                (ret, _tokenObj) = th.initToken(
                    init_param, User("", "", ""), tokenrealm=tokenrealm
                )

                # check policy to set token pin random
                checkPolicyPost("admin", "setPin", {"serial": serial})

            # check the max tokens per realm

            checkPolicyPost("admin", "loadtokens", {"tokenrealm": tokenrealm})
            log.info("[loadtokens] %i tokens imported.", len(TOKENS))

            res = _("%d tokens were imported from the %s file.") % (
                len(TOKENS),
                tokenFile.filename,
            )

            g.audit["info"] = f"{fileType}, {tokenFile} (imported: {len(TOKENS)})"
            g.audit["success"] = ret
            g.audit["serial"] = ", ".join(TOKENS.keys())
            g.audit["token_type"] = ", ".join(
                [token_info.get("type") for token_info in TOKENS.values()]
            )
            g.audit["user"] = ""
            g.audit["realm"] = tokenrealm
            g.reporting["realms"] = {tokenrealm or "/:no realm:/"}

            db.session.commit()
            return sendResultMethod(res, opt={"imported": len(TOKENS)})

        except PolicyException as pex:
            log.error("[loadtokens] Failed checking policy: %r", pex)
            db.session.rollback()
            return sendError(f"{pex!r}", 1)

        except Exception as exx:
            log.error("[loadtokens] failed! %r", exx)
            db.session.rollback()
            return sendErrorMethod(f"{exx!r}")

    @methods(["POST"])
    def testresolver(self):
        """
        This method tests a useridresolvers configuration

        :param name: the name of the resolver

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """

        try:
            try:
                resolvername = self.request_params["name"]

            except KeyError as exx:
                raise ParameterError(_("Missing parameter: %r") % exx) from exx

            if resolvername not in request_context["Resolvers"]:
                msg = f"no such resolver {resolvername!r} defined!"
                raise Exception(msg)

            # ---------------------------------------------------------- --

            # from the request context fetch the resolver details and
            # call the class method 'testconnection' with the retrieved
            # resolver configuration data

            resolver_info = getResolverInfo(resolvername)

            resolver_cls = get_resolver_class(resolver_info["type"])

            if not callable(resolver_cls.testconnection):
                msg = "resolver %r does not support a connection test"
                raise Exception(
                    msg,
                    resolvername,
                )

            (status, desc) = resolver_cls.testconnection(resolver_info["data"])

            res = {"result": status, "desc": desc}

            # TODO
            # set g.audit["success"]
            # `status` sadly has different types....
            # g.audit["success"] = ????

            db.session.commit()
            return sendResult(res)

        except Exception as exx:
            log.error("[testresolver] failed: %r", exx)
            db.session.rollback()
            return sendError(exx, 1)

    @deprecated_methods(["POST"])
    def totp_lookup(self):
        """
        Get information for a past otp value of a TOTP token.
        Includes, when and how long the given OTP was valid.

        :param serial:     (required)   serial number of the token
        :param otp:        (required)   a past OTP value to check
        :param window:     (optional)   the duration to search back from
                                        current time. Defaults to "24h".

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned
        """

        param = self.request_params
        try:
            serial = param.get("serial")
            if not serial:
                msg = "Missing parameter: 'serial'"
                raise ParameterError(msg)

            g.audit["serial"] = serial

            otp = param.get("otp")
            if not otp:
                msg = "Missing parameter: 'otp'"
                raise ParameterError(msg)

            window = param.get("window", "24h")

            # -------------------------------------------------------------- --

            # we require access to at least one token realm

            checkPolicyPre("admin", "totp_lookup", param=param)

            # -------------------------------------------------------------- --

            # lookup of serial and type totp

            tokens = get_tokens(serial=serial, token_type="totp")

            if not tokens:
                g.audit["success"] = False
                g.audit["info"] = "no token found"
                return sendResult(False)

            token = tokens[0]

            g.audit["token_type"] = token.type
            g.audit["user"] = token.getUsername()
            g.audit["realm"] = ", ".join(token.getRealms())

            # -------------------------------------------------------------- --

            # now gather the otp info from the token

            res, opt = token.get_otp_detail(otp=otp, window=window)
            g.audit["success"] = res

            if not res:
                g.audit["info"] = f"no otp {otp!r} found in window {window!r}"

            db.session.commit()
            return sendResult(res, opt=opt)

            # -------------------------------------------------------------- --

        except PolicyException as pe:
            log.error("[totp_lookup] policy failed: %r", pe)
            db.session.rollback()
            return sendError(pe)

        except Exception as exx:
            log.error("[totp_lookup] failed: %r", exx)
            db.session.rollback()
            return sendResult(exx, 0)

    @deprecated_methods(["POST"])
    def checkstatus(self):
        """
        show the status either

        * of one dedicated challenge
        * of all challenges of a token
        * of all challenges belonging to all tokens of a user

        :param transactionid/state:  the transaction id of the challenge
        :param serial: serial number of the token - will show all challenges
        :param user:

        :return: json result of token and challenges

        :raises Exception:
            if an error occurs an exception is serialized and returned
        """

        res = {}

        param = self.request_params.copy()
        only_open_challenges = True

        log.debug("[checkstatus] check challenge token status: %r", param)

        description = """
            admin/checkstatus: check the token status -
            for assynchronous verification. Missing parameter:
            You need to provide one of the parameters "transactionid", "user" or "serial"'
            """

        try:
            checkPolicyPre("admin", "checkstatus")

            transid = param.get("transactionid", None) or param.get("state", None)
            user = request_context["RequestUser"]
            serial = param.get("serial")
            g.audit["serial"] = serial
            all = param.get("open", "False").lower() == "true"

            if all:
                only_open_challenges = False

            if transid is None and not user and serial is None:
                # # raise exception
                log.error(
                    "[admin/checkstatus] : missing parameter: "
                    "transactionid, user or serial number for token"
                )
                msg = f"Usage: {description}"
                raise ParameterError(msg, id=77)

            # # gather all challenges from serial, transactionid and user
            challenges = set()
            if serial is not None:
                challenges.update(
                    Challenges.lookup_challenges(
                        serial=serial, filter_open=only_open_challenges
                    )
                )

            if transid is not None:
                challenges.update(
                    Challenges.lookup_challenges(
                        transid=transid, filter_open=only_open_challenges
                    )
                )

            # if we have a user
            if user:
                tokens = get_tokens(user=user)
                for token in tokens:
                    serial = token.getSerial()
                    challenges.update(
                        Challenges.lookup_challenges(serial=serial, filter_open=True)
                    )

            serials = set()
            for challenge in challenges:
                serials.add(challenge.getTokenSerial())

            status = {}
            realms = set()
            users = set()
            token_types = set()
            # # sort all information by token serial number
            for serial in serials:
                stat = {}
                chall_dict = {}

                # # add the challenges info to the challenge dict
                for challenge in challenges:
                    if challenge.getTokenSerial() == serial:
                        chall_dict[challenge.getTransactionId()] = challenge.get_vars(
                            save=True
                        )
                stat["challenges"] = chall_dict

                # # add the token info to the stat dict
                token = get_token(serial)
                stat["tokeninfo"] = token.get_vars(save=True)

                # # add the local stat to the summary status dict
                status[serial] = stat

                realms.update(token.getRealms())
                users.add(token.getUsername())
                token_types.add(token.type)

            res["values"] = status
            g.audit["success"] = res
            g.audit["serial"] = " ".join(serials)
            g.audit["token_type"] = ", ".join(token_types)
            g.audit["user"] = user.login or ", ".join(users)
            g.audit["realm"] = ", ".join(realms)

            db.session.commit()
            return sendResult(res, 1)

        except PolicyException as pe:
            log.error("[checkstatus] policy failed: %r", pe)
            db.session.rollback()
            return sendError(pe)

        except Exception as exx:
            log.error("[checkstatus] failed: %r", exx)
            db.session.rollback()
            return sendResult(exx, 0)

    # ------------------------------------------------------------------------ -
    @methods(["POST"])
    def unpair(self):
        """resets a token to its unpaired state

        :param serial: the serial number of the token

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """

        try:
            params = self.request_params.copy()

            serial = params.get("serial")
            g.audit["serial"] = serial
            user = request_context["RequestUser"]

            # ---------------------------------------------------------------- -

            # check admin authorization

            checkPolicyPre("admin", "unpair", params, user=user)

            # ---------------------------------------------------------------- -

            tokens = get_tokens(user, serial)

            if not tokens:
                msg = "No token found. Unpairing not possible"
                raise Exception(msg)

            if len(tokens) > 1:
                msg = "Multiple tokens found. Unpairing not possible"
                raise Exception(msg)

            token = tokens[0]

            g.audit["token_type"] = token.type
            g.audit["user"] = token.getUsername()
            g.audit["realm"] = ", ".join(token.getRealms())
            # ---------------------------------------------------------------- -

            token.unpair()

            g.audit["success"] = 1

            db.session.commit()

            # ---------------------------------------------------------------- -

            return sendResult(True)

        # -------------------------------------------------------------------- -

        except Exception as exx:
            log.error("admin/unpair failed: %r", exx)
            g.audit["info"] = str(exx)
            db.session.rollback()
            return sendResult(False, 0, status=False)


# eof ########################################################################
