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
userservice controller -
     This is the controller for the user self service
     interface, where an authenitcated users can manage their own tokens

There are three types of requests
  * the context requests: before, context
  * the auth requests: auth, userinfo
  * the admin requests

At least all admin request must provide the auth cookie and the username
- the auth cookie is verified by decryption
- the username is checked for valid policy acceptance

Remarks:
 * the userinfo request could use the cookie check as it is running after
   the authorization request,  but no policy definition is required
 * the context request might as well run for an authenticated user, thus
   auth request but no policy check

"""

import base64
import json
import logging
from collections import defaultdict

from flask import current_app, g, request
from flask_babel import gettext as _
from werkzeug.exceptions import Forbidden, Unauthorized

from linotp.controllers.base import BaseController, methods
from linotp.flap import config
from linotp.flap import tmpl_context as c
from linotp.lib import deprecated_methods
from linotp.lib.audit.base import get_token_num_info
from linotp.lib.audit.base import search as audit_search
from linotp.lib.auth.validate import ValidationHandler
from linotp.lib.challenges import Challenges
from linotp.lib.config import getFromConfig
from linotp.lib.context import request_context
from linotp.lib.error import ParameterError
from linotp.lib.policy import (
    PolicyException,
    checkOTPPINPolicy,
    checkPolicyPost,
    checkPolicyPre,
    get_client_policy,
    getOTPPINEncrypt,
)
from linotp.lib.policy.action import get_selfservice_action_value
from linotp.lib.realm import getDefaultRealm, getRealms
from linotp.lib.reply import (
    create_img,
    create_img_src,
    sendError,
    sendQRImageResult,
)
from linotp.lib.reply import sendResult as sendResponse
from linotp.lib.reporting import token_reporting
from linotp.lib.resolver import getResolverObject
from linotp.lib.support import LicenseException
from linotp.lib.token import (
    TokenHandler,
    get_multi_otp,
    get_tokens,
    getTokenRealms,
    getTokenType,
    resetToken,
    setPin,
    setPinUser,
)
from linotp.lib.type_utils import boolean
from linotp.lib.user import (
    User,
    get_userinfo,
    getRealmBox,
    getUserFromRequest,
    getUserId,
    splitUser,
)
from linotp.lib.userservice import (
    check_session,
    create_auth_cookie,
    get_context,
    get_cookie_authinfo,
    get_pre_context,
    get_transaction_detail,
    getTokenForUser,
    remove_auth_cookie,
)
from linotp.lib.util import get_client
from linotp.model import db
from linotp.tokens.forwardtoken import ForwardTokenClass

log = logging.getLogger(__name__)

ENCODING = "utf-8"

HASHLIB_MAP = {1: "sha1", 2: "sha256", 3: "sha512"}

# announce available reply channels via reply_mode
# - online: token supports online mode where the user
#   can independently answer the challenge via a
#   different channel without having to enter an OTP.
# - offline: token supports offline mode where the user
#   needs to manually enter an OTP.

REPLY_MODES = defaultdict(
    lambda: ["offline"],
    {
        "push": ["online"],
        "qr": ["offline", "online"],
    },
)
# -------------------------------------------------------------------------- --


def secure_cookie():
    """
    in the development environment where we run in debug mode
    there is probaly no https defined. So we switch secure cookies off.
    this is done in the settings.py
    """
    return config["SESSION_COOKIE_SECURE"]


# -------------------------------------------------------------------------- --


class UserNotFound(Exception):
    pass


def get_auth_user(request):
    """
    retrieve the authenticated user either from
    selfservice or userservice api / remote selfservice

    :param request: the request object
    :return: tuple of (authentication type and authenticated user and
                        authentication state)
    """

    # ---------------------------------------------------------------------- --

    # for the form based selfservice we have the 'user_selfservice' cookie

    selfservice_cookie = request.cookies.get("user_selfservice")

    if selfservice_cookie:
        user, _client, state, _state_data = get_cookie_authinfo(selfservice_cookie)
        auth_type = "user_selfservice"

        return auth_type, user, state

    # ---------------------------------------------------------------------- --

    # for the remote selfservice or userservice api via /userservice/auth
    # we have the 'userauthcookie'

    remote_selfservice_cookie = request.cookies.get("userauthcookie")

    if remote_selfservice_cookie:
        user, _client, state, _state_data = get_cookie_authinfo(
            remote_selfservice_cookie
        )
        auth_type = "userservice"

        return auth_type, user, state

    return "unauthenticated", None, None


def add_and_delete_cookies(response):
    """Given a `Response` object, add or delete cookies as per the
    `g.cookies_to_delete` and `g.cookies` variables.
    """

    [response.delete_cookie(name) for name in g.cookies_to_delete]
    [response.set_cookie(name, **kwargs) for name, kwargs in g.cookies.items()]


def unauthorized(exception, status=401):
    """extend the standard sendResult to handle cookies"""

    response = sendError(exception=exception)

    response.status_code = status

    add_and_delete_cookies(response)

    return Unauthorized(response=response)


def sendResult(obj, id=1, opt=None, status=True):
    """extend the standard sendResult to handle cookies"""

    response = sendResponse(obj=obj, id=id, opt=opt, status=status)

    add_and_delete_cookies(response)

    return response


class UserserviceController(BaseController):
    """
    the interface from the service into linotp to execute the actions for the
    user in the scope of the selfservice

    after the login, the selfservice user gets an auth cookie, which states
    that he already has been authenticated. This cookie is provided on every
    request during which the auth_cookie and session is verified
    """

    jwt_exempt = True  # Don't do JWT auth in this controller

    def set_cookie(self, name, **kwargs):
        g.cookies[name] = kwargs

    def delete_cookie(self, name):
        g.cookies.pop(name, None)

    def __before__(self, **params):
        """
        __before__ is called before every action

        every request to the userservice must pass this place
        here we can check the authorisation for each action and the
        per request general available information

        :param params: list of named arguments
        :return: -nothing- or in case of an error a Response
                created by sendError with the context info 'before'

        """

        # the following actions dont require an authenticated session

        NON_AUTHENTICATED_REQUEST_LIST = [
            "auth",
            "pre_context",
            "login",
            "logout",
        ]

        self.response = None
        g.cookies_to_delete = []
        g.cookies = {}
        g.reporting = {"realms": []}

        action = request_context["action"]

        # We set `g.authUser` to `None` on the off-chance that we're
        # dealing with a request from the
        # `NON_AUTHENTICATED_REQUEST_LIST`. We don't look at the
        # authentication cookie for these (chances are there won't be
        # one, anyway) but we don't want to make problems for
        # downstream consumers of `g.authUser`, such as the
        # `__after__()` method.

        g.authUser = None
        g.client = get_client(request) or ""

        # ------------------------------------------------------------------ --

        # build up general available variables

        context = get_pre_context(g.client)
        g.mfa_login = context["settings"]["mfa_login"]
        g.autoassign = context["settings"]["autoassign"]
        g.autoenroll = context["settings"]["autoenroll"]

        # ------------------------------------------------------------------ --

        # Get the (possibly) authenticated user
        auth_type, identity, auth_state = get_auth_user(request)

        # ------------------------------------------------------------------ --

        # `authUser` is set to the user from the authentication cookie so
        # we can use it elsewhere to refer to the current authenticated user.
        # This includes methods that implement HTTP requests as well as the
        # auditing/accounting code in `__after__()`.

        if identity:
            g.authUser = identity

            c.user = identity.login
            c.realm = identity.realm

        # ------------------------------------------------------------------ --

        # If the request doesn't require authentication, we're done here.

        if action in NON_AUTHENTICATED_REQUEST_LIST:
            return

        # ------------------------------------------------------------------ --

        # every action other than auth, login and pre_context requires a valid
        # session and cookie

        if not identity or auth_type not in [
            "userservice",
            "user_selfservice",
        ]:
            raise unauthorized(_("No valid session"))

        # ------------------------------------------------------------------ --

        # finally check the validty of the session

        if not check_session(request, g.authUser, g.client):
            raise unauthorized(_("No valid session"))

        # ------------------------------------------------------------------ --

        # the usertokenlist could be catched in any identified state

        if action in ["usertokenlist", "userinfo"]:
            return

        # ------------------------------------------------------------------ --

        # any other action requires a full ' state

        if auth_state != "authenticated":
            raise unauthorized(_("No valid session"))

        # ------------------------------------------------------------------ --

        return

    @staticmethod
    def __after__(response):
        """
        __after__ is called after every action

        :param response: the previously created response - for modification
        :return: return the response
        """

        action = request_context["action"]

        auth_user = getUserFromRequest()

        try:
            if g.audit["action"] not in [
                "userservice/context",
                "userservice/pre_context",
                "userservice/userinfo",
            ]:
                if auth_user and isinstance(auth_user, User):
                    user, realm = auth_user.login, auth_user.realm
                else:
                    user = repr(auth_user) if auth_user else ""
                    realm = ""

                g.audit["user"] = user
                g.audit["realm"] = realm

                log.debug(
                    "[__after__] authenticating as %s in realm %s!",
                    g.audit["user"],
                    g.audit["realm"],
                )

                if "serial" in request.args:
                    serial = request.args["serial"]
                    g.audit["serial"] = serial
                    g.audit["token_type"] = getTokenType(serial)

                # --------------------------------------------------------- --

                # actions which change the token amount do some reporting

                if auth_user and action in [
                    "assign",
                    "unassign",
                    "enable",
                    "disable",
                    "enroll",
                    "delete",
                    "finishocra2token",
                ]:
                    event = "token_" + action

                    realms_to_report = g.reporting["realms"]
                    if realms_to_report:
                        token_reporting(event, set(realms_to_report))

                    g.audit["action_detail"] += get_token_num_info()

                current_app.audit_obj.log(g.audit)
                db.session.commit()

            return response

        except Exception as exx:
            log.error("[__after__::%r] exception %r", action, exx)
            db.session.rollback()
            return sendError(exx)

    def _identify_user(self, params):
        """
        identify the user from the request parameters

        the idea of the processing was derived from the former selfservice
        user identification and authentication:
                lib.user.get_authenticated_user
        and has been adjusted to the need to run the password authentication
        as a seperate step

        :param params: request parameters
        :return: User Object or None
        """

        try:
            username = params["login"]
        except KeyError as exx:
            log.error("Missing Key: %r", exx)
            return None

        realm = params.get("realm", "").strip().lower()

        # if we have an realmbox, we take the user as it is
        # - the realm is always given

        if getRealmBox():
            user = User(username, realm, "")
            if user.exists():
                return user

        # if no realm box is given
        #    and realm is not empty:
        #    - create the user from the values (as we are in auto_assign, etc)
        if realm and realm in getRealms():
            user = User(username, realm, "")
            if user.exists():
                return user

        # if the realm is empty or no realm parameter or realm does not exist
        #     - the user could live in the default realm
        else:
            def_realm = getDefaultRealm()
            if def_realm:
                user = User(username, def_realm, "")
                if user.exists():
                    return user

        # if any explicit realm handling had no success, we end up here
        # with the implicit realm handling:

        login, realm = splitUser(username)
        user = User(login, realm)
        if user.exists():
            return user

        return None

    ##########################################################################
    # authentication hooks
    @deprecated_methods(["GET"])
    def auth(self):
        """
        user authentication for example to the remote selfservice

        :param login: login name of the user normaly in the user@realm format
        :param realm: the realm of the user
        :param password: the password for the user authentication
                         which is base32 encoded to seperate the
                         os_passw:pin+otp in case of mfa_login

        :return: {result : {value: bool} }

        :raises Exception:
            if an error occurs an exception is serialized and returned
        """

        try:
            param = self.request_params

            # -------------------------------------------------------------- --

            # identify the user

            user = self._identify_user(params=param)
            if not user:
                log.info("User %r not found", param.get("login"))
                g.audit["action_detail"] = "User {!r} not found".format(
                    param.get("login")
                )
                g.audit["success"] = False
                return sendResult(False, 0)

            uid = f"{user.login}@{user.realm}"

            g.authUser = user

            # -------------------------------------------------------------- --

            # extract password

            try:
                password = param["password"]
            except KeyError:
                log.info("Missing password for user %r", uid)
                g.audit["action_detail"] = f"Missing password for user {uid!r}"
                g.audit["success"] = False
                return sendResult(False, 0)

            (otp, passw) = password.split(":")
            otp = base64.b32decode(otp)
            passw = base64.b32decode(passw)

            # -------------------------------------------------------------- --

            # check the authentication

            if g.mfa_login:
                res = self._mfa_login_check(user, passw, otp)

            else:
                res = self._default_auth_check(user, passw, otp)

            if not res:
                log.info("User %r failed to authenticate!", uid)
                g.audit["action_detail"] = f"User {uid!r} failed to authenticate!"
                g.audit["success"] = False
                return sendResult(False, 0)

            # -------------------------------------------------------------- --

            log.debug("Successfully authenticated user %s:", uid)

            (cookie_value, expires, expiration) = create_auth_cookie(user, g.client)

            self.set_cookie(
                "userauthcookie",
                value=cookie_value,
                secure=secure_cookie(),
                expires=expires,
            )

            g.audit["action_detail"] = f"expires: {expiration} "
            g.audit["success"] = True

            db.session.commit()
            return sendResult(True, 0)

        except Exception as exx:
            g.audit["info"] = (f"{exx!r}")[:80]
            g.audit["success"] = False

            db.session.rollback()
            return sendError(exx)

    def _login_with_cookie(self, cookie, params):
        """
        verify the mfa login second step
        - the credentials have been verified in the first step, so that the
          authentication state is either 'credentials_verified' or
          'challenge_triggered'

        :param cookie: preserving the authentication state
        :param params: the request parameters
        """
        user, _client, auth_state, _state_data = get_cookie_authinfo(cookie)

        if not user:
            msg = "no user info in authentication cache"
            raise UserNotFound(msg)

        g.authUser = user
        request_context["selfservice"] = {"state": auth_state, "user": user}

        if auth_state == "credentials_verified":
            return self._login_with_cookie_credentials(cookie, params)

        elif auth_state == "challenge_triggered":
            return self._login_with_cookie_challenge(cookie, params)

        else:
            msg = f"unknown state {auth_state!r}"
            raise NotImplementedError(msg)

    def _login_with_cookie_credentials(self, cookie, params):
        """
        verify the mfa login second step
        - the credentials have been verified in the first step, so that the
          authentication state is 'credentials_verified'

        :param cookie: preserving the authentication state

        :param params: the request parameters
        """

        user, _client, _auth_state, _state_data = get_cookie_authinfo(cookie)

        # -------------------------------------------------------------- --

        otp = params.get("otp", "")
        serial = params.get("serial")

        # in case of a challenge trigger, provide default qr and push settings
        if "data" not in params and "content_type" not in params:
            params["data"] = _("Selfservice Login Request\nUser: %s") % (
                user.login if user else ""
            )
            params["content_type"] = 0

        vh = ValidationHandler()

        if "serial" in params:
            res, reply = vh.checkSerialPass(serial, passw=otp, options=params)
        else:
            res, reply = vh.checkUserPass(user, passw=otp, options=params)

        # -------------------------------------------------------------- --

        # if res is True: success for direct authentication and we can
        # set the cookie for successful authenticated

        if res:
            ret = create_auth_cookie(user, g.client)
            (cookie, expires, _exp) = ret

            self.set_cookie(
                "user_selfservice",
                value=cookie,
                secure=secure_cookie(),
                expires=expires,
            )

            g.audit["success"] = True
            g.audit["info"] = f"User {user!r} authenticated from otp"

            db.session.commit()
            return sendResult(res, 0)

        # -------------------------------------------------------------- --

        # if res is False and reply is provided, a challenge was triggered
        # and we set the state 'challenge_triggered'

        if not res and reply:
            if "message" in reply and "://chal/" in reply["message"]:
                reply["img_src"] = create_img_src(reply["message"])

            ret = create_auth_cookie(
                user,
                g.client,
                state="challenge_triggered",
                state_data=reply,
            )
            cookie, expires, expiration = ret

            self.set_cookie(
                "user_selfservice",
                value=cookie,
                secure=secure_cookie(),
                expires=expires,
            )

            g.audit["success"] = False

            # -------------------------------------------------------------- --

            # determine the tokentype and adjust the offline, online reply

            token_type = reply.get("linotp_tokentype")
            used_token_type = (
                token_type
                if token_type != "forward"
                else reply.get("linotp_forward_tokentype")
            )
            reply["replyMode"] = REPLY_MODES[used_token_type]

            # ------------------------------------------------------ --

            # add transaction data wrt to the new spec

            if reply.get("img_src"):
                reply["transactionData"] = reply["message"]

            # ------------------------------------------------------ --

            # care for the messages as it is done with verify

            if used_token_type == "qr":
                reply["message"] = _("Please scan the provided qr code")

            # ------------------------------------------------------ --

            # adjust the transactionid to transactionId for api conformance

            if "transactionid" in reply:
                transaction_id = reply["transactionid"]
                del reply["transactionid"]
                reply["transactionId"] = transaction_id

            db.session.commit()
            return sendResult(False, 0, opt=reply)

        # -------------------------------------------------------------- --

        # if no reply and res is False, the authentication failed

        if not res and not reply:
            db.session.commit()
            return sendResult(False, 0)

    def _login_with_cookie_challenge(self, cookie, params):
        """
        verify the mfa login second step
        - the credentials have been verified in the first step and a challenge
          has been triggered, so that the authentication state is
          'challenge_triggered'

        :param cookie: preserving the authentication state
        :param params: the request parameters
        """
        user, _client, _auth_state, state_data = get_cookie_authinfo(cookie)

        if not state_data:
            msg = "invalid state data"
            raise Exception(msg)

        # if there has been a challenge triggerd before, we can extract
        # the the transaction info from the cookie cached data

        transid = state_data.get("transactionid")

        if "otp" in params:
            return self._login_with_cookie_challenge_check_otp(user, transid, params)

        return self._login_with_cookie_challenge_check_status(user, transid)

    def _login_with_cookie_challenge_check_otp(self, user, transid, params):
        """Verify challenge against the otp.

        check if it is a valid otp, we grant access

        state: challenge_tiggered

        :param user: the login user
        :param transid: the transaction id, taken from the cookie context
        :param params: all input parameters
        """

        vh = ValidationHandler()
        res, _reply = vh.check_by_transactionid(
            transid, passw=params["otp"], options={"transactionid": transid}
        )

        if res:
            (cookie, expires, expiration) = create_auth_cookie(user, g.client)

            self.set_cookie(
                "user_selfservice",
                value=cookie,
                secure=secure_cookie(),
                expires=expires,
            )

            g.audit["success"] = True
            g.audit["action_detail"] = f"expires: {expiration} "
            g.audit["info"] = f"{user!r} logged in "

        db.session.commit()
        return sendResult(res, 0)

    def _login_with_cookie_challenge_check_status(self, user, transid):
        """Check status of the login challenge.

        check, if there is no otp in the request, we assume that we have to
        poll for the transaction state. If a valid tan was recieved we grant
        access.

        input state: challenge_tiggered

        :param user: the login user
        :param transid: the transaction id, taken out of the cookie content
        """

        va = ValidationHandler()
        ok, opt = va.check_status(transid=transid, user=user, password="")

        verified = False
        if ok and opt:
            verified = (
                opt.get("transactions", {}).get(transid, {}).get("valid_tan", False)
            )

        if verified:
            (cookie, expires, expiration) = create_auth_cookie(user, g.client)

            self.set_cookie(
                "user_selfservice",
                value=cookie,
                secure=secure_cookie(),
                expires=expires,
            )

            g.audit["success"] = True
            g.audit["action_detail"] = f"expires: {expiration} "
            g.audit["info"] = f"{user!r} logged in "

        detail = get_transaction_detail(transid)

        db.session.commit()
        return sendResult(verified, opt=detail)

    def _login_with_otp(self, user, passw, param):
        """
        handle login with otp - either if provided directly or delayed

        :param user: User Object of the identified user
        :param password: the password parameter
        :param param: the request parameters
        """

        if not user.checkPass(passw):
            log.info("User %r failed to authenticate!", user)
            g.audit["action_detail"] = f"User {user!r} failed to authenticate!"
            g.audit["success"] = False

            db.session.commit()
            return sendResult(False, 0)

        # ------------------------------------------------------------------ --

        # if there is an otp, we can do a direct otp authentication

        otp = param.get("otp", "")
        if otp:
            vh = ValidationHandler()
            res, reply = vh.checkUserPass(user, passw + otp)

            if res:
                log.debug("Successfully authenticated user %r:", user)

                (cookie_value, expires, expiration) = create_auth_cookie(user, g.client)

                self.set_cookie(
                    "user_selfservice",
                    value=cookie_value,
                    secure=secure_cookie(),
                    expires=expires,
                )

                g.audit["action_detail"] = f"expires: {expiration} "
                g.audit["info"] = f"{user!r} logged in "

            elif not res and reply:
                log.error("challenge trigger though otp is provided")

            g.audit["success"] = res

            db.session.commit()
            return sendResult(res, 0, reply)

        # ------------------------------------------------------------------ --

        # last step - we have no otp but mfa_login request - so we
        # create the 'credentials_verified state'

        (cookie_value, expires, expiration) = create_auth_cookie(
            user, g.client, state="credentials_verified"
        )

        self.set_cookie(
            "user_selfservice",
            value=cookie_value,
            secure=secure_cookie(),
            expires=expires,
        )

        tokenList = getTokenForUser(g.authUser, active=True, exclude_rollout=False)

        reply = {
            "message": "credential verified - "
            "additional authentication parameter required",
            "tokenList": tokenList,
        }

        g.audit["action_detail"] = f"expires: {expiration} "
        g.audit["info"] = f"{user!r} credentials verified"

        g.audit["success"] = True
        db.session.commit()

        return sendResult(False, 0, opt=reply)

    def _login_with_password_only(self, user, password):
        """
        simple old password authentication

        :param user: the identified user
        :param password: the password
        """

        res = user.checkPass(password)

        if res:
            (cookie_value, expires, _expiration) = create_auth_cookie(user, g.client)

            self.set_cookie(
                "user_selfservice",
                value=cookie_value,
                secure=secure_cookie(),
                expires=expires,
            )

        g.audit["success"] = res
        g.audit["info"] = f"{user!r} logged in "

        db.session.commit()

        return sendResult(res, 0)

    @deprecated_methods(["GET"])
    def login(self):
        """
        user authentication for example to the remote selfservice

        :param login: login name of the user normaly in the user@realm format
        :param realm: the realm of the user
        :param password: the password for the user authentication
        :param otp: optional the otp

        :return: {result : {value: bool} }

        :raises Exception:
            if an error occurs an exception is serialized and returned
        """

        try:
            param = self.request_params.copy()

            # -------------------------------------------------------------- --

            # the new selfservice provides the parameter 'username' instead of
            # 'login'. As all lower llayers expect 'login' we switch the case

            if "login" not in param and "username" in param:
                param["login"] = param["username"]
                del param["username"]

            # -------------------------------------------------------------- --

            # if this is an pre-authenticated login we continue
            # with the authentication states

            user_selfservice_cookie = request.cookies.get("user_selfservice")

            # check if this cookie is still valid

            auth_info = get_cookie_authinfo(user_selfservice_cookie)

            if auth_info[0] and check_session(request, auth_info[0], auth_info[1]):
                return self._login_with_cookie(user_selfservice_cookie, param)

            # if there is a cookie but could not be found in cache
            # we remove the out dated client cookie

            if user_selfservice_cookie and not auth_info[0]:
                self.delete_cookie("user_selfservice")

            # -------------------------------------------------------------- --

            # identify the user

            user = self._identify_user(params=param)
            if not user:
                msg = "user {!r} not found!".format(param.get("login"))
                raise UserNotFound(msg)

            g.authUser = user

            # -------------------------------------------------------------- --

            password = param["password"]

            if g.mfa_login:
                # allow the mfa login for users that have no token till now
                # if the policy 'mfa_passOnNoToken' is defined with password
                # only

                tokenArray = getTokenForUser(g.authUser)

                policy = get_client_policy(
                    client=g.client,
                    scope="selfservice",
                    action="mfa_passOnNoToken",
                    userObj=user,
                    active_only=True,
                )

                if policy and not tokenArray:
                    return self._login_with_password_only(user, password)

                return self._login_with_otp(user, password, param)

            else:
                return self._login_with_password_only(user, password)

            # -------------------------------------------------------------- --

        except (Unauthorized, Forbidden) as exx:
            log.error("userservice login failed: %r", exx)

            g.audit["info"] = (f"{exx!r}")[:80]
            g.audit["success"] = False

            raise exx

        except Exception as exx:
            log.error("userservice login failed: %r", exx)

            g.audit["info"] = (f"{exx!r}")[:80]
            g.audit["success"] = False

            db.session.rollback()
            return sendResult(False, 0)

    def _default_auth_check(self, user, password, otp=None):
        """
        the former selfservice login controll:
         check for username and os_pass

        :param user: user object
        :param password: the expected os_password
        :param otp: not used

        :return: bool
        """
        (uid, _resolver, resolver_class) = getUserId(user)
        r_obj = getResolverObject(resolver_class)
        res = r_obj.checkPass(uid, password)
        return res

    def _mfa_login_check(self, user, password, otp):
        """
        secure auth requires the os password and the otp (pin+otp)
        - secure auth supports autoassignement, where the user logs in with
                      os_password and only the otp value. If user has no token,
                      a token with a matching otp in the window is searched
        - secure auth supports autoenrollment, where a user with no token will
                      get automaticaly enrolled one token.

        :param user: user object
        :param password: the os_password
        :param otp: empty (for autoenrollment),
                    otp value only for auto assignment or
                    pin+otp for standard authentication (respects
                                                            otppin ploicy)

        :return: bool
        """
        ret = False

        passwd_match = self._default_auth_check(user, password, otp)

        if passwd_match:
            toks = getTokenForUser(user, active=True)

            # if user has no token, we check for auto assigneing one to him
            if len(toks) == 0:
                th = TokenHandler()

                # if no token and otp, we might do an auto assign
                if g.autoassign and otp:
                    ret = th.auto_assignToken(password + otp, user)

                # if no token no otp, we might trigger an aouto enroll
                elif g.autoenroll and not otp:
                    (auto_enroll_return, reply) = th.auto_enrollToken(password, user)
                    if auto_enroll_return is False:
                        error = "autoenroll: {!r}".format(reply.get("error", ""))
                        raise Exception(error)
                    # we always have to return a false, as we have
                    # a challenge tiggered
                    ret = False

            # user has at least one token, so we do a check on pin + otp
            else:
                vh = ValidationHandler()
                (ret, _reply) = vh.checkUserPass(user, otp)
        return ret

    @deprecated_methods(["POST"])
    def usertokenlist(self):
        """
        This returns a tokenlist as html output

        :param active: (optional) True or False - should only active or inactive tokens be returned
                        default is to show both

        :return: a tokenlist as html output

        :raises Exception:
            if an error occurs an exception is serialized and returned
        """

        try:
            if self.request_params.get("active", "").lower() in [
                "true"
            ] or self.request_params.get("active", "").lower() in ["false"]:
                active = True
            else:
                active = None

            tokenArray = getTokenForUser(
                g.authUser, active=active, exclude_rollout=False
            )

            g.audit["success"] = True

            db.session.commit()
            return sendResult(tokenArray, 0)

        except Exception as exx:
            log.error("failed with error: %r", exx)
            db.session.rollback()
            return sendError(exx)

    @deprecated_methods(["POST"])
    def userinfo(self):
        """
        hook for the auth, which requests additional user info

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned
        """

        try:
            uinfo = get_userinfo(g.authUser)
            db.session.commit()
            return sendResult(uinfo, 0)

        except Exception as exx:
            db.session.rollback()
            error = f"error ({exx!r}) "
            log.error(error)
            return f"<pre>{error}</pre>"

        finally:
            db.session.close()

    def logout(self):
        """
        hook for the auth, which deletes the cookies of the current session

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned
        """

        try:
            cookie = request.cookies.get("user_selfservice")
            remove_auth_cookie(cookie)
            self.delete_cookie("user_selfservice")

            g.audit["success"] = True

            db.session.commit()
            return sendResult(True, 0)

        except Exception as exx:
            db.session.rollback()
            error = f"error ({exx!r}) "
            log.error(error)
            return f"<pre>{error}</pre>"

        finally:
            log.debug("done")

    ##########################################################################
    # context setup functions
    @deprecated_methods(["POST"])
    def pre_context(self):
        """
        This is the authentication to self service
        If you want to do ANYTHING with selfservice, you need to be
        authenticated. The _before_ is executed before any other function
        in this controller.

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """
        try:
            pre_context = get_pre_context(g.client)
            return sendResult(True, opt=pre_context)

        except Exception as exx:
            log.error("pre_context failed with error: %r", exx)
            db.session.rollback()
            return sendError(exx)

    @deprecated_methods(["POST"])
    def context(self):
        """
        This is the authentication to self service
        If you want to do ANYTHING with selfservice, you need to be
        authenticated. The _before_ is executed before any other function
        in this controller.

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned
        """

        try:
            context = get_context(config, g.authUser, g.client)
            return sendResult(True, opt=context)

        except Exception as e:
            log.error("[context] failed with error: %r", e)
            db.session.rollback()
            return sendError(e)

    # action hooks for the js methods ########################################
    @methods(["POST"])
    def enable(self):
        """
        enables a token or all tokens of a user

        as this is a controller method, the parameters are taken from
        BaseController.request_params

        :param serial: serial number of the token *required
        :param user: username in format user@realm *required

        :return: a linotp json doc with result {u'status': True, u'value': 2}

        """
        param = self.request_params
        res = {}
        log.debug("remoteservice enable to enable/disable a token")

        try:
            try:
                serial = param["serial"]
            except KeyError as exx:
                msg = f"Missing parameter: '{exx}'"
                raise ParameterError(msg) from exx

            # check selfservice authorization
            checkPolicyPre("selfservice", "userenable", param, authUser=g.authUser)
            th = TokenHandler()
            if th.isTokenOwner(serial, g.authUser):
                log.info(
                    "[userenable] user %s@%s is enabling his token with serial %s.",
                    g.authUser.login,
                    g.authUser.realm,
                    serial,
                )
                ret = th.enableToken(True, None, serial)
                res["enable token"] = ret

                g.audit["realm"] = g.authUser.realm
                g.reporting["realms"] = [g.authUser.realm or "/:no realm:/"]
                g.audit["success"] = ret

            db.session.commit()
            return sendResult(res, 1)

        except PolicyException as pe:
            log.error("[enable] policy failed %r", pe)
            db.session.rollback()
            return sendError(pe, 1)

        except LicenseException as lex:
            log.error("[enable] license exception: %r", lex)
            db.session.rollback()
            msg = _("Failed to enable token, please contact your administrator")
            return sendError(msg, 1)

        except Exception as e:
            log.error("[enable] failed: %r", e)
            db.session.rollback()
            return sendError(e, 1)

    ########################################################
    @methods(["POST"])
    def disable(self):
        """
        disables a token

        as this is a controller method, the parameters are taken from
        BaseController.request_params

        :param serial: serial number of the token *required
        :param user: username in format user@realm *required

        :return: a linotp json doc with result {u'status': True, u'value': 2}

        """
        param = self.request_params
        res = {}
        log.debug("remoteservice disable a token")

        try:
            try:
                serial = param["serial"]
            except KeyError as exx:
                msg = f"Missing parameter: '{exx}'"
                raise ParameterError(msg) from exx

            # check selfservice authorization
            checkPolicyPre("selfservice", "userdisable", param, authUser=g.authUser)
            th = TokenHandler()
            if th.isTokenOwner(serial, g.authUser):
                log.info(
                    "user %s@%s is disabling his token with serial %s.",
                    g.authUser.login,
                    g.authUser.realm,
                    serial,
                )
                ret = th.enableToken(False, None, serial)
                res["disable token"] = ret

                g.audit["realm"] = g.authUser.realm
                g.reporting["realms"] = [g.authUser.realm or "/:no realm:/"]
                g.audit["success"] = ret

            db.session.commit()
            return sendResult(res, 1)

        except PolicyException as pe:
            log.error("policy failed %r", pe)
            db.session.rollback()
            return sendError(pe, 1)

        except Exception as e:
            log.error("failed: %r", e)
            db.session.rollback()
            return sendError(e, 1)

    @methods(["POST"])
    def delete(self):
        """
        This is the internal delete token function that is called from within
        the self service portal. The user is only allowed to delete token,
        that belong to him.

        :param serial: the serial number of the token

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned
        """
        param = self.request_params
        res = {}

        try:
            # check selfservice authorization
            checkPolicyPre("selfservice", "userdelete", param, g.authUser)

            try:
                serial = param["serial"]
            except KeyError as exx:
                msg = f"Missing parameter: '{exx}'"
                raise ParameterError(msg) from exx

            th = TokenHandler()
            if th.isTokenOwner(serial, g.authUser):
                log.info(
                    "[userdelete] user %s@%s is deleting his token with serial %s.",
                    g.authUser.login,
                    g.authUser.realm,
                    serial,
                )
                ret = th.removeToken(serial=serial)
                res["delete token"] = ret

                g.audit["realm"] = g.authUser.realm
                g.reporting["realms"] = [g.authUser.realm or "/:no realm:/"]
                g.audit["success"] = ret

            db.session.commit()
            return sendResult(res, 1)

        except PolicyException as pe:
            log.error("[userdelete] policy failed: %r", pe)
            db.session.rollback()
            return sendError(pe, 1)

        except Exception as e:
            log.error(
                "[userdelete] deleting token %s of user %s failed!",
                serial,
                c.user,
            )
            db.session.rollback()
            return sendError(e, 1)

    @methods(["POST"])
    def reset(self):
        """
        This internally resets the failcounter of the given token.

        :param serial: the serial number of the token

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned
        """
        res = {}
        param = self.request_params
        serial = None

        try:
            checkPolicyPre("selfservice", "userreset", param, g.authUser)
            try:
                serial = param["serial"]
            except KeyError as exx:
                msg = f"Missing parameter: '{exx}'"
                raise ParameterError(msg) from exx

            th = TokenHandler()
            if th.isTokenOwner(serial, g.authUser) is True:
                log.info(
                    "[userreset] user %s@%s is resetting the failcounter"
                    " of his token with serial %s",
                    g.authUser.login,
                    g.authUser.realm,
                    serial,
                )
                ret = resetToken(serial=serial)
                res["reset Failcounter"] = ret

                g.audit["success"] = ret

            db.session.commit()
            return sendResult(res, 1)

        except PolicyException as pe:
            log.error("policy failed: %r", pe)
            db.session.rollback()
            return sendError(pe, 1)

        except Exception as e:
            log.error("error resetting token with serial %s: %r", serial, e)
            db.session.rollback()
            return sendError(e, 1)

    @methods(["POST"])
    def unassign(self):
        """
        This is the internal unassign function that is called from within
        the self service portal. The user is only allowed to unassign token,
        that belong to him.

        :param serial: the serial number of the token

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """
        param = self.request_params
        res = {}

        try:
            # check selfservice authorization
            checkPolicyPre("selfservice", "userunassign", param, g.authUser)

            try:
                serial = param["serial"]
            except KeyError as exx:
                msg = f"Missing parameter: '{exx}'"
                raise ParameterError(msg) from exx

            upin = param.get("pin", None)

            th = TokenHandler()
            if th.isTokenOwner(serial, g.authUser) is True:
                log.info(
                    "user %s@%s is unassigning his token with serial %s.",
                    g.authUser.login,
                    g.authUser.realm,
                    serial,
                )

                ret = th.unassignToken(serial, None, upin)
                res["unassign token"] = ret

                g.audit["realm"] = g.authUser.realm
                g.reporting["realms"] = [
                    g.authUser.realm or "/:no realm:/",
                    "/:no realm:/",
                ]
                g.audit["success"] = ret

            db.session.commit()
            return sendResult(res, 1)

        except PolicyException as pe:
            log.error("policy failed: %r", pe)
            db.session.rollback()
            return sendError(pe, 1)

        except Exception as e:
            log.error("unassigning token %s of user %s failed! %r", serial, c.user, e)
            db.session.rollback()
            return sendError(e, 1)

    @methods(["POST"])
    def setpin(self):
        """
        When the user hits the set pin button, this function is called.

        :param serial: the serial number of the token
        :param userpin: the pin for the token

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned
        """
        res = {}
        param = self.request_params

        # # if there is a pin
        try:
            # check selfservice authorization
            checkPolicyPre("selfservice", "usersetpin", param, g.authUser)

            try:
                userPin = param["userpin"]
                serial = param["serial"]
            except KeyError as exx:
                msg = f"Missing parameter: '{exx}'"
                raise ParameterError(msg) from exx

            th = TokenHandler()
            if th.isTokenOwner(serial, g.authUser) is True:
                log.info(
                    "user %s@%s is setting the OTP PIN for token with serial %s",
                    g.authUser.login,
                    g.authUser.realm,
                    serial,
                )

                check_res = checkOTPPINPolicy(userPin, g.authUser)

                if not check_res["success"]:
                    log.warning(
                        "Setting of OTP PIN for Token %s by user %s failed: %s",
                        serial,
                        g.authUser.login,
                        check_res["error"],
                    )

                    return sendError(_("Error: %s") % check_res["error"])

                if getOTPPINEncrypt(serial=serial, user=g.authUser) == 1:
                    param["encryptpin"] = "True"
                ret = setPin(userPin, None, serial, param)
                res["set userpin"] = ret

                g.audit["success"] = ret

            db.session.commit()
            return sendResult(res, 1)

        except PolicyException as pex:
            log.error("policy failed: %r", pex)
            db.session.rollback()
            return sendError(pex, 1)

        except Exception as exx:
            log.error("Error setting OTP PIN: %r", exx)
            db.session.rollback()
            return sendError(exx, 1)

    @methods(["POST"])
    def setmpin(self):
        """
        When the user hits the set pin button, this function is called.

        :param serial: the serial number of the token
        :param pin: the pin for the token

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned
        """
        res = {}
        param = self.request_params
        # # if there is a pin
        try:
            # check selfservice authorization
            checkPolicyPre("selfservice", "usersetmpin", param, g.authUser)
            try:
                pin = param["pin"]
                serial = param["serial"]
            except KeyError as exx:
                msg = f"Missing parameter: '{exx}'"
                raise ParameterError(msg) from exx

            th = TokenHandler()
            if th.isTokenOwner(serial, g.authUser) is True:
                log.info(
                    "user %s@%s is setting the mOTP PIN for token with serial %s",
                    g.authUser.login,
                    g.authUser.realm,
                    serial,
                )
                ret = setPinUser(pin, serial)
                res["set userpin"] = ret

                g.audit["success"] = ret

            db.session.commit()
            return sendResult(res, 1)

        except PolicyException as pex:
            log.error("policy failed: %r", pex)
            db.session.rollback()
            return sendError(pex, 1)

        except Exception as exx:
            log.error("Error setting the mOTP PIN %r", exx)
            db.session.rollback()
            return sendError(exx, 1)

    @methods(["POST"])
    def resync(self):
        """
        This is the internal resync function that is called from within
        the self service portal

        :param serial: the serial number of the token
        :param otp1: the first otp for the sequence
        :param otp2: the second otp for the sequence

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """

        res = {}
        param = self.request_params
        serial = "N/A"

        try:
            # check selfservice authorization
            checkPolicyPre("selfservice", "userresync", param, g.authUser)

            try:
                serial = param["serial"]
                otp1 = param["otp1"]
                otp2 = param["otp2"]
            except KeyError as exx:
                msg = f"Missing parameter: '{exx}'"
                raise ParameterError(msg) from exx

            th = TokenHandler()
            if th.isTokenOwner(serial, g.authUser) is True:
                log.info(
                    "user %s@%s is resyncing his token with serial %s",
                    g.authUser.login,
                    g.authUser.realm,
                    serial,
                )
                ret = th.resyncToken(otp1, otp2, None, serial)
                res["resync Token"] = ret

                g.audit["success"] = ret

            db.session.commit()
            return sendResult(res, 1)

        except PolicyException as pe:
            log.error("policy failed: %r", pe)
            db.session.rollback()
            return sendError(pe, 1)

        except Exception as e:
            log.error("error resyncing token with serial %s:%r", serial, e)
            db.session.rollback()
            return sendError(e, 1)

    @deprecated_methods(["GET"])
    def verify(self):
        """
        verify a token, identified by a serial number

        after a successful authentication and a valid session, the idenitfied
        user can verify his enrolled tokens. To verify the token, the token
        serial number is used.

        for direct authenticating tokens like hmac and totp, the parameter otp
        is required:

        a valid verification request example would be:

              https://.../userservice/verify?serial=token_serial&otp=123456&session=...

        replied by the usual /validate/check json response

        {
             "jsonrpc": "2.XX",
               "result": {
                  "status": true,
                  "value": true
               },
               "version": "LinOTP 2.XX",
               "id": 1
        }

        :param serial:
        :param transactionid:
        :param otp:
        :param session:

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """

        try:
            params = self.request_params

            checkPolicyPre("selfservice", "userverify", params, g.authUser)

            # -------------------------------------------------------------- --

            # setup - get the tokens from the serial or transactionid/state

            transaction_id = params.get("transactionid", params.get("state"))
            serial = params.get("serial")

            if not serial and not transaction_id:
                msg = "Missing parameter: serial or transactionid"
                raise ParameterError(msg)

            # -------------------------------------------------------------- --

            # check for invalid params

            supported_params = ["serial", "transactionid", "otp", "session"]
            unknown_params = [p for p in params if p not in supported_params]
            if len(unknown_params) > 0:
                msg = f"unsupported parameters: {unknown_params!r}"
                raise ParameterError(msg)

            # -------------------------------------------------------------- --

            # identify the affected tokens
            if transaction_id:
                reply = Challenges.get_challenges(transid=transaction_id)
                _expired_challenges, valid_challenges = reply

                if _expired_challenges:
                    msg = "challenge already expired!"
                    raise Exception(msg)

                if not valid_challenges:
                    msg = "no valid challenge found!"
                    raise Exception(msg)

                if len(valid_challenges) != 1:
                    msg = (
                        "Could not uniquely identify challenge for "
                        f"transaction id {transaction_id} "
                    )
                    raise Exception(msg)

                _challenge = valid_challenges[0]

                serials = {c.tokenserial for c in valid_challenges}

                tokens = [
                    token for serial in serials for token in get_tokens(serial=serial)
                ]

            elif serial:
                tokens = get_tokens(serial=serial)

            # -------------------------------------------------------------- --

            # now there are all tokens identified either by serial or by
            # transaction id, we can do the sanity checks that there is only
            # one token which belongs to the authenticated user

            if len(tokens) == 0:
                msg = "no token found!"
                raise Exception(msg)

            if len(tokens) > 1:
                msg = "multiple tokens found!"
                raise Exception(msg)

            token = tokens[0]

            th = TokenHandler()
            if not th.isTokenOwner(token.getSerial(), g.authUser):
                msg = "User is not token owner"
                raise Exception(msg)

            # -------------------------------------------------------------- --

            # determine which action is meant

            action = None

            # verify the transaction if we have an otp
            if transaction_id and "otp" in params:
                action = "verify transaction"

            # only a transaction id, so we query the transaction status
            elif transaction_id and "otp" not in params:
                action = "query transaction"

            # if no transaction id but otp, we directly verify the otp
            elif not transaction_id and "otp" in params:
                action = "verify otp"

            # no transaction id and no OTP - trigger a challenge
            elif not transaction_id and "otp" not in params:
                action = "trigger challenge"

            # -------------------------------------------------------------- --

            if action == "verify transaction":
                vh = ValidationHandler()
                (res, _opt) = vh.check_by_transactionid(
                    transid=transaction_id, passw=params["otp"], options=params
                )

                g.audit["success"] = res
                db.session.commit()
                return sendResult(res)

            # -------------------------------------------------------------- --

            elif action == "query transaction":
                detail = get_transaction_detail(transaction_id)
                res = detail.get("valid_tan", False)
                g.audit["success"] = res

                db.session.commit()
                return sendResult(res, opt=detail)

            # -------------------------------------------------------------- --

            elif action == "verify otp":
                vh = ValidationHandler()
                (res, _opt) = vh.checkUserPass(
                    g.authUser, passw=params["otp"], options=params
                )

                g.audit["success"] = res

                db.session.commit()
                return sendResult(res)

            # -------------------------------------------------------------- --

            # challenge request:

            elif action == "trigger challenge":
                transaction_data = None
                transaction_id = None

                # 'authenticate': default for non-challenge response tokens
                #                 like ['hmac', 'totp', 'motp']
                used_token_type = token.type
                if isinstance(token, ForwardTokenClass):
                    used_token_type = token.targetToken.type

                if "authenticate" in token.mode:
                    message = _("Please enter your otp")

                # 'challenge': tokens that do not have a direct authentication
                #              mode need a challenge to be tested

                elif "challenge" in token.mode:
                    data = _(
                        "SelfService token test\n\nToken: {0}\nSerial: {1}\nUser: {2}"
                    ).format(
                        token.type,
                        token.token.LinOtpTokenSerialnumber,
                        g.authUser.login,
                    )

                    options = {"content_type": "0", "data": data}

                    res, reply = Challenges.create_challenge(token, options=options)
                    if not res:
                        msg = f"failed to trigger challenge {reply:r}"
                        raise Exception(msg)

                    if used_token_type == "qr":
                        transaction_data = reply["message"]
                        message = _("Please scan the provided qr code")

                    else:
                        message = reply["message"]

                    transaction_id = reply["transactionid"]

                else:
                    msg = "unsupported token mode"
                    raise Exception(msg)

                # -------------------------------------------------- --
                # create the challenge detail response

                detail_response = {
                    "message": message,  # localized user facing message
                    "replyMode": REPLY_MODES[used_token_type],
                }

                if transaction_id:
                    detail_response["transactionId"] = transaction_id

                if transaction_data:
                    detail_response["transactionData"] = transaction_data

                if isinstance(token, ForwardTokenClass):
                    # get the target token info.
                    target_token_info = token._get_target_info()

                    # and add info about this token to the detail
                    detail_response.update(target_token_info)
                # ------------------------------------------------- --
                # close down the session and submit the result

                db.session.commit()
                return sendResult(False, opt=detail_response)

        except PolicyException as pe:
            log.error("policy failed: %r", pe)
            db.session.rollback()
            return sendError(pe)

        except Exception as exx:
            g.audit["success"] = False
            log.error("error verifying token with serial %s: %r", serial, exx)
            db.session.rollback()
            return sendError(exx, 1)

    @methods(["POST"])
    def assign(self):
        """
        This is the internal assign function that is called from within
        the self service portal

        :param serial: the token serial
        :param description: an optional description
        :param pin: the new token pin

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """
        param = self.request_params
        res = {}

        try:
            description = param.get("description", None)
            upin = param.get("pin", None)

            try:
                serial = param["serial"]
            except KeyError as exx:
                msg = f"Missing parameter: '{exx}'"
                raise ParameterError(msg) from exx

            # check selfservice authorization
            checkPolicyPre("selfservice", "userassign", param, g.authUser)

            # check if token is in another realm
            source_realms = getTokenRealms(serial)
            if g.authUser.realm.lower() not in source_realms and len(source_realms):
                # if the token is assigned to realms, then the user must be in
                # one of the realms, otherwise the token can not be assigned
                raise Exception(
                    _("The token you want to assign is not contained in your realm!")
                )
            th = TokenHandler()

            if th.hasOwner(serial):
                raise Exception(_("The token is already assigned to another user."))
            # -------------------------------------------------------------- --

            # assign token to user

            log.info(
                "user %s@%s is assign the token with serial %s to himself.",
                g.authUser.login,
                g.authUser.realm,
                serial,
            )

            ret_assign = th.assignToken(serial, g.authUser, upin)

            # -------------------------------------------------------------- --

            # if we have a description, we set it to the token

            if ret_assign and description:
                log.info("set description of token %s", serial)
                th.setDescription(description, serial=serial)

            # -------------------------------------------------------------- --

            res["assign token"] = ret_assign

            g.audit["realm"] = g.authUser.realm
            source_realms_reporting = source_realms or ["/:no realm:/"]
            g.reporting["realms"] = [
                *source_realms_reporting,
                g.authUser.realm or "/:no realm:/",
            ]
            g.audit["success"] = ret_assign

            checkPolicyPost("selfservice", "userassign", param, g.authUser)

            db.session.commit()
            return sendResult(res, 1)

        except PolicyException as pe:
            log.error("[userassign] policy failed: %r", pe)
            db.session.rollback()
            return sendError(pe, 1)

        except Exception as exx:
            log.error("[userassign] token assignment failed! %r", exx)
            db.session.rollback()
            return sendError(exx, 1)

    @deprecated_methods(["POST"])
    def getSerialByOtp(self):
        """

        searches for the token, that generates the given OTP value.
        The search can be restricted by several critterions
        This method only searches tokens in the realm of the user
        and tokens that are not assigned!


        :param otp: (required) Will search for the token, that produces this OTP value
        :param type: (optional) will only search in tokens of type

        :return:
            a json result with a boolean status and serial in the result

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """
        param = self.request_params
        res = {}
        try:
            # check selfservice authorization
            checkPolicyPre("selfservice", "usergetserialbyotp", param, g.authUser)
            try:
                otp = param["otp"]
            except KeyError as exx:
                msg = f"Missing parameter: '{exx}'"
                raise ParameterError(msg) from exx

            ttype = param.get("type", None)

            g.audit["token_type"] = ttype
            th = TokenHandler()
            serial, _username, _resolverClass = th.get_serial_by_otp(
                None, otp, 10, typ=ttype, realm=g.authUser.realm, assigned=0
            )
            res = {"serial": serial}

            g.audit["success"] = True
            g.audit["serial"] = serial

            db.session.commit()
            return sendResult(res, 1)

        except PolicyException as pe:
            log.error("policy failed: %r", pe)
            db.session.rollback()
            return sendError(pe, 1)

        except Exception as exx:
            log.error("token getSerialByOtp failed! %r", exx)
            db.session.rollback()
            return sendError(exx, 1)

    @methods(["POST"])
    def enroll(self):
        """
        Enroll a token.

        .. note::
            Depending on the token type more parameters have to be provided
            as http parameters

        .. deprecated:: 4.0
            The ``detail.googleurl`` field in the response is deprecated and will be
            removed in version 5.0. Please use ``detail.enrollment_url`` instead.

        :param type: one of (hmac, totp, pw, ...)
        :param serial: a suggested serial number
        :param prefix: a prefix for the serial number
        :param description: an optional description for the token
        :param pin: the pin for the token (policy: setOTPPIN)
        :param otppin: motpPin for mOTP Tokens (policy: setMOTPPIN)

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """
        response_detail = {}
        param = self.request_params.copy()

        try:
            try:
                tok_type = param["type"]
            except KeyError as exx:
                msg = f"Missing parameter: '{exx}'"
                raise ParameterError(msg) from exx

            # check selfservice authorization
            checkPolicyPre("selfservice", "userinit", param, g.authUser)

            # Check setOTPPIN Permission
            # and raise Exception when user sends pin without Permission
            # or when user does not send pin when it is required
            try:
                checkPolicyPre("selfservice", "usersetpin", param, g.authUser)
                has_setOTPPIN_policy = True
            except PolicyException:
                has_setOTPPIN_policy = False
            pin_in_params = "pin" in param
            if has_setOTPPIN_policy and not pin_in_params:
                msg = f"Enrolling Token by user {g.authUser.login} failed because they send no pin when it was required by policy setOTPPIN"
                log.warning(msg)
                raise PolicyException(msg)
            if not has_setOTPPIN_policy and pin_in_params:
                msg = f"Enrolling Token by user {g.authUser.login} failed because they send pin when it was not allowed by policy setOTPPIN"
                log.warning(msg)
                raise PolicyException(msg)

            if pin_in_params:
                pin = param.get("pin")
                # Validate PIN
                check_res = checkOTPPINPolicy(pin, g.authUser)
                if not check_res["success"]:
                    log.warning(
                        "Enrolling Token by user %s failed: %s",
                        g.authUser.login,
                        check_res["error"],
                    )

                    return sendError(_("Error: %s") % check_res["error"])

            serial = param.get("serial", None)
            prefix = param.get("prefix", None)

            # --------------------------------------------------------- --

            # enrollment of hotp (hmac), totp, or motp token

            if tok_type in ["hmac", "totp", "motp"] and "otpkey" not in param:
                param["genkey"] = param.get("genkey", "1")

            if tok_type == "hmac":
                # --------------------------------------------------------- --

                # query for hmac_otplen

                hmac_otplen = get_selfservice_action_value(
                    "hmac_otplen", user=g.authUser, default=6
                )

                param["otplen"] = param.get("otplen", hmac_otplen)

                # --------------------------------------------------------- --

                # query for hashlib

                hmac_hashlib = get_selfservice_action_value(
                    "hmac_hashlib", user=g.authUser, default=1
                )

                param["hashlib"] = param.get("hashlib", HASHLIB_MAP[hmac_hashlib])

            elif tok_type == "totp":
                # --------------------------------------------------------- --

                # query for timestep

                totp_timestep = get_selfservice_action_value(
                    "totp_timestep", user=g.authUser, default=30
                )

                param["timeStep"] = param.get("timeStep", totp_timestep)

                # --------------------------------------------------------- --

                # query for totp_otplen

                totp_otplen = get_selfservice_action_value(
                    "totp_otplen", user=g.authUser, default=6
                )

                param["otplen"] = param.get("totp_otplen", totp_otplen)

                # --------------------------------------------------------- --

                # query for totp hashlib

                totp_hashlib = get_selfservice_action_value(
                    "totp_hashlib", user=g.authUser, default=1
                )

                param["hashlib"] = param.get("totp_hashlib", HASHLIB_MAP[totp_hashlib])

            th = TokenHandler()
            if not serial:
                serial = th.genSerial(tok_type, prefix)
                param["serial"] = serial

            desc = param.get("description", "")

            log.info(
                "[userinit] initialize a token with serial %s "
                "and type %s by user %s@%s",
                serial,
                tok_type,
                g.authUser.login,
                g.authUser.realm,
            )

            log.debug(
                "[userinit] Initializing the token serial: %s,"
                " desc: %s, for user %s @ %s.",
                serial,
                desc,
                g.authUser.login,
                g.authUser.realm,
            )

            # extend the interface by parameters, so that decisssion could
            # be made in the token update method
            param["::scope::"] = {"selfservice": True, "user": g.authUser}

            (ret, tokenObj) = th.initToken(param, g.authUser)
            if tokenObj is not None and hasattr(tokenObj, "getInfo"):
                info = tokenObj.getInfo()
                response_detail.update(info)

            # result enrichment - if the token is sucessfully created,
            # some processing info is added to the result document,
            #  e.g. the otpkey :-) as qr code
            initDetail = tokenObj.getInitDetail(param, g.authUser)
            response_detail.update(initDetail)

            # -------------------------------------------------------------- --

            g.audit["success"] = ret
            g.audit["serial"] = response_detail.get("serial", "")
            g.reporting["realms"] = [g.authUser.realm or "/:no realm:/"]

            # -------------------------------------------------------------- --

            # in the checkPolicyPost for selfservice, the serial is used

            if "serial" not in param:
                param["serial"] = response_detail.get("serial", "")

            # -------------------------------------------------------------- --

            checkPolicyPost("selfservice", "enroll", param, user=g.authUser)

            db.session.commit()

            # # finally we render the info as qr image, if the qr parameter
            # # is provided and if the token supports this
            if "qr" in param and tokenObj is not None:
                (rdata, hparam) = tokenObj.getQRImageData(response_detail)
                hparam.update(response_detail)
                hparam["qr"] = param.get("qr") or "html"
                return sendQRImageResult(rdata, hparam)
            else:
                return sendResult(ret, opt=response_detail)

        except PolicyException as pe:
            log.error("[userinit] policy failed: %r", pe)
            db.session.rollback()
            return sendError(pe, 1)

        except LicenseException as lex:
            log.error("[enroll] license exception: %r", lex)
            db.session.rollback()
            msg = _("Failed to enroll token, please contact your administrator")
            return sendError(msg, 1)

        except Exception as e:
            log.error("[userinit] token initialization failed! %r", e)
            db.session.rollback()
            return sendError(e, 1)

    @deprecated_methods(["POST"])
    def getmultiotp(self):
        """
        Using this function the user may receive OTP values for his own tokens.

        :param count: number of otp values to return

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """

        getotp_active = boolean(getFromConfig("linotpGetotp.active", False))
        if not getotp_active:
            return sendError(_("getotp is not activated."), 0)

        param = self.request_params
        ret = {}

        try:
            try:
                serial = param["serial"]
                count = int(param["count"])
            except KeyError as exx:
                msg = f"Missing parameter: '{exx}'"
                raise ParameterError(msg) from exx

            curTime = param.get("curTime", None)

            th = TokenHandler()
            if th.isTokenOwner(serial, g.authUser) is False:
                error = _("The serial %s does not belong to user %s@%s") % (
                    serial,
                    g.authUser.login,
                    g.authUser.realm,
                )
                log.error(error)
                return sendError(error, 1)

            max_count = checkPolicyPre("selfservice", "max_count", param, g.authUser)
            log.debug("checkpolicypre returned %s", max_count)

            count = min(count, max_count)

            log.debug("[usergetmultiotp] retrieving OTP value for token %s", serial)
            ret = get_multi_otp(serial, count=int(count), curTime=curTime)
            if ret["result"] is False and max_count == -1:
                ret["error"] = "{} - {}".format(
                    ret["error"],
                    _("see policy definition."),
                )

            ret["serial"] = serial
            g.audit["success"] = True

            db.session.commit()
            return sendResult(ret, 0)

        except PolicyException as pe:
            log.error("[usergetmultiotp] policy failed: %r", pe)
            db.session.rollback()
            return sendError(pe, 1)

        except Exception as e:
            log.error("[usergetmultiotp] gettoken/getmultiotp failed: %r", e)
            db.session.rollback()
            return sendError(_("selfservice/usergetmultiotp failed: %r") % e, 0)

    @deprecated_methods(["POST"])
    def history(self):
        """
        This returns the list of the tokenactions of this user
        It returns the audit information for the given search pattern

        key, value pairs as search patterns.

        or: Usually the key=values will be locally AND concatenated.
            it a parameter or=true is passed, the filters will be OR
            concatenated.

            The Flexigrid provides us the following parameters:
                ('page', u'1'), ('rp', u'100'),
                ('sortname', u'number'),
                ('sortorder', u'asc'),
                ('query', u''), ('qtype', u'serial')]
        :param page:
        :param rp:
        :param sortname:
        :param sortorder:
        :param query:

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """

        param = self.request_params
        res = {}

        try:
            log.debug("params: %r", param)
            checkPolicyPre("selfservice", "userhistory", param, g.authUser)

            lines, total, page = audit_search(
                param,
                user=g.authUser,
                columns=[
                    "date",
                    "action",
                    "success",
                    "serial",
                    "token_type",
                    "administrator",
                    "action_detail",
                    "info",
                ],
            )

            if not total:
                total = len(lines)

            res = {"page": page, "total": total, "rows": lines}

            g.audit["success"] = True

            db.session.commit()
            return json.dumps(res, indent=3)

        except PolicyException as pe:
            log.error("[search] policy failed: %r", pe)
            db.session.rollback()
            return sendError(pe, 1)

        except Exception as exx:
            log.error("[search] audit/search failed: %r", exx)
            db.session.rollback()
            return sendError(_("audit/search failed: %s") % str(exx), 0)

    @methods(["POST"])
    def activateocratoken(self):
        """
        activateocratoken - called from the selfservice web ui to activate the OCRA token

        :param type:    'ocra2'
        :param serial:    serial number of the token
        :param activationcode: the calculated activation code

        :return:    dict about the token
                 { 'activate': True, 'ocratoken' : {
                        'url' :     url,
                        'img' :     '<img />',
                        'label' :   "%s@%s" % (g.authUser.login,
                                                   g.authUser.realm),
                        'serial' :  serial,
                    }  }
        :raises Exception:
            if an error occurs an exception is serialized and returned

        """
        param = self.request_params
        ret = {}

        try:
            # check selfservice authorization

            checkPolicyPre("selfservice", "useractivateocra2token", param, g.authUser)

            try:
                typ = param["type"]
            except KeyError as exx:
                msg = f"Missing parameter: '{exx}'"
                raise ParameterError(msg) from exx

            if typ and typ.lower() not in ["ocra2"]:
                return sendError(
                    _("valid types is 'ocra2'. You provided %s") % typ,
                )

            helper_param = {}
            helper_param["type"] = typ
            try:
                helper_param["serial"] = param["serial"]
            except KeyError as exx:
                msg = f"Missing parameter: '{exx}'"
                raise ParameterError(msg) from exx

            acode = param["activationcode"]
            helper_param["activationcode"] = acode.upper()

            try:
                helper_param["genkey"] = param["genkey"]
            except KeyError as exx:
                msg = f"Missing parameter: '{exx}'"
                raise ParameterError(msg) from exx

            th = TokenHandler()
            (ret, tokenObj) = th.initToken(helper_param, g.authUser)

            info = {}
            serial = ""
            if tokenObj is not None:
                info = tokenObj.getInfo()
                serial = tokenObj.getSerial()
            else:
                msg = "Token not found!"
                raise Exception(msg)

            url = info.get("app_import")
            trans = info.get("transactionid")

            ret = {
                "url": url,
                "img": create_img(url, width=400, alt=url),
                "label": f"{g.authUser.login}@{g.authUser.realm}",
                "serial": serial,
                "transaction": trans,
            }

            g.audit["serial"] = serial
            g.audit["token_type"] = typ
            g.audit["success"] = True
            g.audit["realm"] = g.authUser.realm

            db.session.commit()
            return sendResult({"activate": True, "ocratoken": ret})

        except PolicyException as pe:
            log.error("policy failed: %r", pe)
            db.session.rollback()
            return sendError(pe, 1)

        except Exception as exx:
            log.error("token initialization failed! %r", exx)
            db.session.rollback()
            return sendError(exx, 1)

    @methods(["POST"])
    def finishocra2token(self):
        """

        finishocra2token - called from the selfservice web ui to finish
                        the OCRA2 token to run the final check_t for the token

        :param passw: the calculated verificaton otp
        :param transactionid: the transactionid

        :return: dict about the token

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """

        param = self.request_params.copy()

        if "session" in param:
            del param["session"]

        value = {}
        ok = False
        typ = ""
        opt = None

        try:
            typ = param.get("type", None)
            if not typ:
                msg = "Missing parameter: type"
                raise ParameterError(msg)

            # check selfservice authorization

            checkPolicyPre("selfservice", "userwebprovision", param, g.authUser)

            passw = param.get("pass", None)
            if not passw:
                msg = "Missing parameter: pass"
                raise ParameterError(msg)

            transid = param.get("state", param.get("transactionid", None))
            if not transid:
                msg = "Missing parameter: state or transactionid!"
                raise ParameterError(msg)

            vh = ValidationHandler()
            (ok, reply) = vh.check_by_transactionid(
                transid=transid, passw=passw, options=param
            )

            value["value"] = ok
            value["failcount"] = int(reply.get("failcount", 0))

            g.audit["transactionid"] = transid
            g.audit["token_type"] = reply["token_type"]
            g.audit["success"] = ok
            g.audit["realm"] = g.authUser.realm
            g.reporting["realms"] = [g.authUser.realm or "/:no realm:/"]

            db.session.commit()
            return sendResult(value, opt)

        except PolicyException as pe:
            log.error("[userfinishocra2token] policy failed: %r", pe)
            db.session.rollback()
            return sendError(pe, 1)

        except Exception as e:
            error = f"[userfinishocra2token] token initialization failed! {e!r}"
            log.error(error)
            db.session.rollback()
            return sendError(error, 1)

    @methods(["POST"])
    def setdescription(self):
        """
        sets a description for a token, provided the setDescription policy is set.

        as this is a controller method, the parameters are taken from
        BaseController.request_params

        :param serial: serial number of the token *required
        :param description: string containing a new description for the token

        :return: a linotp json doc with result {'status': True, 'value': True}

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """

        log.debug("set token description")

        try:
            param = self.request_params

            try:
                serial = param["serial"]
                description = param["description"]

            except KeyError as exx:
                msg = f"Missing parameter: '{exx}'"
                raise ParameterError(msg) from exx

            checkPolicyPre("selfservice", "usersetdescription", param, g.authUser)

            th = TokenHandler()

            if not th.isTokenOwner(serial, g.authUser):
                msg = f"User {g.authUser.login!r} is not owner of the token"
                raise Exception(msg)

            log.info(
                "user %s@%s is changing description of token with serial %s.",
                g.authUser.login,
                g.authUser.realm,
                serial,
            )

            ret = th.setDescription(description, serial=serial)

            res = {"set description": ret}

            g.audit["realm"] = g.authUser.realm
            g.audit["success"] = ret

            db.session.commit()
            return sendResult(res, 1)

        except PolicyException as pex:
            log.error("[setdescription] policy failed")
            db.session.rollback()
            return sendError(pex, 1)

        except Exception as exx:
            log.error("failed: %r", exx)
            db.session.rollback()
            return sendError(exx, 1)


# eof##########################################################################
