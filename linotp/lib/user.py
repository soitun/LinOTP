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
"""contains user - related functions"""

import json
import logging
import re
from functools import partial

from flask import g

from linotp.lib.cache import get_cache
from linotp.lib.config import getFromConfig, getLinotpConfig, storeConfig
from linotp.lib.context import request_context
from linotp.lib.error import UserError
from linotp.lib.realm import (
    createDBRealm,
    getDefaultRealm,
    getRealms,
    setDefaultRealm,
)
from linotp.lib.resolver import (
    getResolverClassName,
    getResolverList,
    getResolverObject,
    parse_resolver_spec,
)
from linotp.useridresolver.UserIdResolver import ResolverNotAvailable

ENCODING = "utf-8"

log = logging.getLogger(__name__)


class NoResolverFound(Exception):
    pass


class User:
    def __init__(self, login="", realm="", resolver_config_identifier=""):
        self.login = login
        self.realm = realm
        self.resolver_config_identifier = resolver_config_identifier

        self.info = {}
        self.exist = False
        self._exists = None

        self.resolverUid = {}
        self.resolverConf = {}
        self.resolvers_list = []

    def _filter_for_resolver_config_identifier(self, resolvers_list):
        """
        filter_for_resolver_spec filters a list of resolvers:
        - if no resolver_config_identifier exists
            the original list of resolvers is returned

        - if no resolver_config_identifier exists
            and if it is in the resolver list:
                a list with this resolver is returned or
                an empty list is returned

        """

        if not self.resolver_config_identifier:
            return resolvers_list

        for resolver_spec in set(resolvers_list):
            if (
                resolver_spec.rpartition(".")[-1]
                == self.resolver_config_identifier.rpartition(".")[-1]
            ):
                return [resolver_spec]

        return []

    def get_uid_resolver(self, resolvers=None):
        """
        generator to get the uid and resolver info of the user

        :param resolvers: provide the resolver, where to check for the user
        :return: the tuple of uid and resolver
        """

        uid = None
        resolvers_list = []

        # if the resolver is not provided, we make a lookup for all resolvers
        # in the user realm

        if not resolvers:
            if self.realm:
                realms = getRealms()

                if self.realm.lower() in realms:
                    resolvers_list = get_resolvers_of_user(
                        self.login, self.realm.lower()
                    )

                    if not resolvers_list:
                        log.info(
                            "user %r not found in realm %r",
                            self.login,
                            self.realm,
                        )

        else:
            resolvers_list = []
            for search_resolver in resolvers:
                fq_resolver = User.get_fq_resolver(search_resolver)
                if fq_resolver:
                    resolvers_list.append(fq_resolver)

        # if there is a resolver_config_identifier we have to care for

        filtered_resolvers_list = self._filter_for_resolver_config_identifier(
            resolvers_list
        )

        for resolver_spec in filtered_resolvers_list:
            try:
                # we can use the user in resolver lookup cache
                # instead of asking the resolver

                _login, uid, _user_info = lookup_user_in_resolver(
                    self.login, None, resolver_spec
                )

                if not any((_login, uid, _user_info)):
                    continue

                # we add the gathered resolver info to our self for later usage

                # 1. to the resolver uid list

                self.resolverUid[resolver_spec] = uid

                # 2. the resolver spec list
                y = getResolverObject(resolver_spec)
                resId = y.getResolverId()
                resCId = resolver_spec
                __, conf = parse_resolver_spec(resolver_spec)
                self.resolverConf[resolver_spec] = (resId, resCId, conf)

                # remember that we identified the user
                self.exist = True

                yield uid, resolver_spec

            except Exception as exx:
                log.error("Error while accessing resolver %r", exx)

    def __str__(self):
        if not self.login and not self.realm:
            return "None"

        if self.resolver_config_identifier:
            return f"{self.login}@{self.realm} ({self.resolver_config_identifier})"
        else:
            return f"{self.login}@{self.realm}"

    def __repr__(self):
        ret = f"User(login={self.login!r}, realm={self.realm!r}, conf={self.resolver_config_identifier!r} ::resolverUid:{self.resolverUid!r}, resolverConf:{self.resolverConf!r})"
        return ret

    @staticmethod
    def get_fq_resolver(res):
        fq_resolver = None
        resolvers = getResolverList()
        if res in resolvers:
            match_res = resolvers.get(res)
            fq_resolver = getResolverClassName(
                match_res["type"], match_res["resolvername"]
            )
        return fq_resolver

    def getUserInfo(self, resolver=None):
        userInfo = {}

        lookup_resolvers = None
        if resolver:
            lookup_resolvers = [resolver]

        try:
            (userid, resolver_spec) = next(self.get_uid_resolver(lookup_resolvers))
        except StopIteration:
            return {}

        try:
            y = getResolverObject(resolver_spec)
            log.debug(
                "[getUserInfo] Getting user info for userid >%r< in resolver",
                userid,
            )
            userInfo = y.getUserInfo(userid)
            self.info[resolver_spec] = userInfo

        except Exception as exx:
            log.error(
                "[getUserInfo][ resolver with specification %r not found: %r ]",
                resolver_spec,
                exx,
            )

        return userInfo

    def getRealms(self):
        """
        return all realms in which the user is located

        :return: list of realms
        """

        if not self.exists():
            return [self.realm or getDefaultRealm()]

        realms = list(
            {
                realm
                for realm, realm_definition in getRealms().items()
                if self.resolver in realm_definition.get("useridresolver", [])
            }
        )

        return realms

    def getResolvers(self):
        return list(self.resolverUid.keys())

    def addResolverUId(self, resolver, uid, conf="", resId="", resCId=""):
        self.resolverUid[resolver] = uid
        self.resolverConf[resolver] = (resId, resCId, conf)

    def getResolverUId(self, resolver_spec):
        return self.resolverUid.get(resolver_spec, "")

    def getResolverConf(self, resolver_spec):
        return self.resolverConf.get(resolver_spec, "")

    def getUserPerConf(self):
        """
        a wildcard usr (realm = *) could have multiple configurations
        this method will return a list of uniq users, one per configuration

        :return: list of users
        """
        resolvers = self.getResolvers()
        if len(resolvers) == 1:
            return [self]

        # if we have multiple resolvers in this wildcard user
        # we create one user per config and add this user to the list
        # of all users to be checked
        userlist = []
        for resolver in resolvers:
            (resId, resClass, resConf) = self.getResolverConf(resolver)
            uid = self.getResolverUId(resolver)
            n_user = User(self.login)
            n_user.addResolverUId(resClass, uid, resConf, resId, resClass)
            userlist.append(n_user)

        return userlist

    def get_full_qualified_names(self):
        """Get full qualified names.

        :return: list of full qualified names
        """

        fqn = []

        fqn.append(self.login)

        if self.realm:
            fqn.append(f"{self.login}@{self.realm}")

        if self.resolver_config_identifier:
            fqn.append(f"{self.login}.{self.resolver_config_identifier}:")

        return fqn

    def exists(self):
        """
        check if a user exists in the given realm
        """
        if self._exists in [True, False]:
            return self._exists

        self._exists = False

        realms = getRealms(self.realm.lower())
        if not realms:
            return self._exists

        for realm_name, definition in realms.items():
            resolvers = definition.get("useridresolver", [])
            for realm_resolver in resolvers:
                log.debug("checking in %r", realm_resolver)
                resolver_obj = getResolverObject(realm_resolver)
                if resolver_obj:
                    log.debug("checking in module %r", resolver_obj)
                    uid = resolver_obj.getUserId(self.login)
                    if uid:
                        log.debug("type of uid: %s", type(uid))
                        log.debug("type of realm_resolver: %s", type(realm_resolver))
                        self._exists = True
                        self.realm = realm_name
                        self.uid = uid
                        self.resolver = realm_resolver
                        return self._exists
                else:
                    log.error("module %r not found!", realm_resolver)

        return self._exists

    def checkPass(self, password):
        if self.exists() is False:
            return False

        res = False

        try:
            y = getResolverObject(self.resolver)
            res = y.checkPass(self.uid, password)

        except Exception:
            log.error("Failed to check user password")

        return res

    def getPermissions(self):
        from linotp.lib.policy.permissions import UserPermissions  # noqa: PLC0415

        return UserPermissions(self)

    def __ne__(self, other):
        """
        operator to support user comparison: user1 != user2

        a user is the same if he has the same uid and the same realm or
        resolver - in case the user is a virtual one like manage admin, we
        only can rely on the login name

        """

        if not self.exists() or not other.exists():
            if self.login != other.login:
                return True

        else:
            self_info = self.getUserInfo()
            other_info = other.getUserInfo()

            if self_info["userid"] != other_info["userid"]:
                return True

        if self.realm:
            return self.realm != other.realm

        return bool(self.resolverConf and self.resolverConf != other.resolverConf)

    def __eq__(self, other):
        """support for: user1 == user2"""
        return not self.__ne__(other)

    def __bool__(self):
        """support for: if user:"""
        if self.login is None:
            return False
        return len(self.login) > 0


def getUserResolverId(user, report=False):
    """get the resolver id of the user"""

    log.debug("getUserResolverId for %r", user)

    if not user:
        return ("", "", "")

    try:
        return getUserId(user)

    except Exception as exx:
        log.error(
            "[getUserResolverId] for %r@%r failed: %r",
            user.login,
            user.realm,
            exx,
        )

        if report is True:
            msg = f"getUserResolverId failed: {exx!r}"
            raise UserError(msg, id=1112) from exx
        return ("", "", "")


def splitUser(username):
    """
    split the username into the user and realm

    :param username: the given username
    :return: tuple of (user and group/realm)
    """

    user = username.strip()
    group = ""

    if "@" in user:
        (user, group) = user.rsplit("@", 1)
    elif "\\" in user:
        (group, user) = user.split("\\", 1)

    return (user, group)


def _get_resolver_from_param(param):
    """
    extract the resolver shortname from the given parameter,
    which could be "res_name (fq resolver name) "
    """

    resolver_config_identifier = param.get("resConf", "")

    if not resolver_config_identifier or "(" not in resolver_config_identifier:
        return resolver_config_identifier

    resolver_config_id, __ = resolver_config_identifier.split("(")
    return resolver_config_id.strip()


def get_user_from_options(options_dict, fallback_user=None, fallback_realm=None):
    """
    return a tuple of user login and realm considering the options contexts

    in the token implementation we often require to make a policy lookup.
    As the policies are user and realm dependent we require to define for
    witch user or realm this lookup should be made. The input can be taken
    from:
    - the token owner or
    - options, the request additional parameters which might contain a user
      object or a login name or
    - the token realm, if neither user or owner is given

    :param options_dict: the request options dict with the user
    :param fallback_user: which should be set with the token owner
    :param fallback_realm: which should be set with the token realm

    :return: the tuple with user login and realm
    """

    options = options_dict or {}
    user = fallback_user or User()

    if options.get("user"):
        if isinstance(options["user"], str):
            user = getUserFromParam(options)

        elif isinstance(options["user"], User):
            user = options["user"]

        else:
            log.warning("unknown type of user object %r", options["user"])

    realm = user.realm
    login = user.login or ""

    if not login and not user.realm:
        realm = fallback_realm

    return login, realm


def getUserFromParam(param):
    """
    establish an user object from the request parameters
    """

    log.debug("[getUserFromParam] entering function")

    realm = param.get("realm", "")
    login = param.get("user", "")
    resolver_config_id = _get_resolver_from_param(param)

    log.debug("[getUserFromParam] got user <<%r>>", login)

    # ---------------------------------------------------------------------- --

    if not login and not realm and not resolver_config_id:
        return User()

    # ---------------------------------------------------------------------- --

    if realm:
        usr = User(
            login=login,
            realm=realm,
            resolver_config_identifier=resolver_config_id,
        )

        return usr

    # ---------------------------------------------------------------------- --

    # no realm but a user!

    splitAtSign = getFromConfig("splitAtSign", "true")

    if splitAtSign.lower() == "true":
        (login, realm) = splitUser(login)

    if login and not realm:
        realm = getDefaultRealm()

    # ---------------------------------------------------------------------- --

    # everything ready to create the user

    usr = User(login, realm, resolver_config_identifier=resolver_config_id)

    # ---------------------------------------------------------------------- --

    # if no resolver determined, we try to extend the user info

    if "resConf" not in param:
        res = getResolversOfUser(usr)

        #
        # if nothing is found, we try to find fall back to the
        # user definition like u@r

        if not res and "realm" not in param and "@" in usr.login:
            ulogin, _, urealm = usr.login.rpartition("@")

            if urealm.lower() in getRealms():
                realm = urealm
                login = ulogin
                usr = User(ulogin, urealm)
                res = getResolversOfUser(usr)

        usr.resolvers_list = res

    log.debug(
        "[getUserFromParam] creating user object %r,%r,%r",
        login,
        realm,
        resolver_config_id,
    )
    log.debug("[getUserFromParam] created user object %r ", usr)

    return usr


def getUserFromRequest():
    """
    This function returns the logged-in user as object

    :return: the authenticated user as user object or None
    """
    return getattr(g, "authUser", None)


def get_userinfo(user: User, secure: bool = True) -> dict:
    """ "
    gather information about a user to be returned for rendering

    - to ease the rendering process, in case of an error we just return an
      empty structure and log the errors

    :param user: User class object
    :param secure: defines if the crypted password will be part of the
                   returned structure
    """

    uinfo = {"realm": "", "resolver": "", "username": ""}

    try:
        (uid, resolver, resolver_class) = getUserId(user)
        uinfo = getUserInfo(uid, resolver, resolver_class)

        if secure and "cryptpass" in uinfo:
            del uinfo["cryptpass"]

        uinfo["realm"] = user.realm
        uinfo["resolver"] = resolver.rpartition(".")[-1]

    except Exception as exx:
        log.error("failed to gather user information %r", exx)

    return uinfo


def setRealm(realm, resolvers):
    realm = realm.lower().strip()
    realm = realm.replace(" ", "-")

    nameExp = r"^[A-Za-z0-9_\-\.]*$"
    res = re.match(nameExp, realm)
    if res is None:
        e = Exception(
            f"non conformant characters in realm name: {realm} (not in {nameExp})"
        )
        raise e

    ret = storeConfig(f"useridresolver.group.{realm}", resolvers)
    if ret is False:
        return ret

    createDBRealm(realm)

    # if this is the first one, make it the default
    realms = getRealms()
    if len(realms) == 0:
        setDefaultRealm(realm, check_if_exists=False)

    # clean the realm cache
    delete_realm_resolver_cache(realm)

    return True


def getUserRealms(user, allRealms=None, defaultRealm=None):
    """
    Returns the realms, a user belongs to.
    If the user has no realm but only a useridresolver, than all realms,
    containing this resolver are returned.
    This function is used for the policy module
    """
    if not allRealms:
        allRealms = getRealms()

    defRealm = getDefaultRealm().lower() if not defaultRealm else defaultRealm.lower()

    Realms = []
    if user.realm == "" and user.resolver_config_identifier == "":
        defRealm = getDefaultRealm().lower()
        Realms.append(defRealm)
        user.realm = defRealm
    elif user.realm != "":
        Realms.append(user.realm.lower())
    else:
        # we got a resolver and will get all realms the resolver belongs to.
        for key, val in allRealms.items():
            log.debug("[getUserRealms] evaluating realm %r: %r ", key, val)
            for reso in val["useridresolver"]:
                resotype, resoname = reso.rsplit(".", 1)
                log.debug(
                    "[getUserRealms] found resolver %r of type %r",
                    resoname,
                    resotype,
                )
                if resoname == user.resolver_config_identifier:
                    Realms.append(key.lower())
                    log.debug(
                        "[getUserRealms] added realm %r to Realms due to resolver %r",
                        key,
                        user.resolver_config_identifier,
                    )

    return Realms


def getRealmBox():
    """
    returns the config value of selfservice.realmbox.
    if True, the realmbox in the selfservice login will be displayed.
    if False, the realmbox will not be displayed and the user needs to login
              via user@realm
    """
    rb_string = "linotp.selfservice.realmbox"
    log.debug("[getRealmBox] getting realmbox setting")
    conf = getLinotpConfig()
    if rb_string in conf:
        log.debug("[getRealmBox] read setting: %r", conf[rb_string])
        return conf[rb_string] == "True"
    else:
        return False


def getSplitAtSign():
    """
    returns the config value of splitAtSign.
    if True, the username should be split if there is an at sign.
    if False, the username will be taken unchanged for loginname.
    """
    splitAtSign = getFromConfig("splitAtSign", "true") or "true"
    return splitAtSign.lower() == "true"


def find_resolver_spec_for_config_identifier(realms_dict, config_identifier):
    """
    Iterates through a realms dictionary, extracts the resolver specification
    and returns it, when its config identifier matches the provided
    config_identifier argument

    :param realms_dict: A realms dictionary
    :param config_identifier: The config identifier to search for

    :return Resolver specification (or None if no match occurred)
    """

    # FIXME: Exactly as the old algorithm this method
    # assumes, that the config_identifier is globally
    # unique. This is not necessarily the case

    for realm_dict in realms_dict.values():
        resolver_specs = realm_dict["useridresolver"]
        for resolver_spec in resolver_specs:
            __, current_config_identifier = parse_resolver_spec(resolver_spec)
            if current_config_identifier.lower() == config_identifier.lower():
                return resolver_spec

    return None


def getResolvers(user):
    """
    get the list of the Resolvers within a users.realm
    or from the resolver conf, if given in the user object

    :note:  It ignores the user.login attribute!

    :param user: User with realm or resolver conf
    :type  user: User object
    """

    realms = getRealms()
    default_realm = getDefaultRealm()

    if user.resolver_config_identifier:
        resolver_spec = find_resolver_spec_for_config_identifier(
            realms, user.resolver_config_identifier
        )

        if resolver_spec is not None:
            return [resolver_spec]

    user_realm = user.realm.strip().lower()

    if user_realm and user_realm in realms:
        lookup_realms = {user_realm}
    elif user_realm.endswith("*"):
        pattern = user.realm.strip()[:-1]
        lookup_realms = {r for r in realms if r.startswith(pattern)}
    elif user_realm == "*":
        lookup_realms = set(realms)
    elif user_realm and user_realm not in realms:
        lookup_realms = set()
    elif default_realm:
        lookup_realms = {default_realm}
    else:
        lookup_realms = set()

    # finally try to get the reolvers for the user

    resolver_set = set()

    user_login = user.login.strip()

    for lookup_realm in lookup_realms:
        if user_login and "*" not in user_login:
            user_resolvers = get_resolvers_of_user(user.login, lookup_realm)
            if not user_resolvers:
                log.info("no user %r found in realm %r", user.login, lookup_realm)

        else:
            user_resolvers = realms[lookup_realm]["useridresolver"]

        resolver_set.update(user_resolvers)

    return list(resolver_set)


def getResolversOfUser(user):
    """
    getResolversOfUser returns the list of the Resolvers of a user
    in a given realm. A user can be be in more than one resolver
    if the login name is the same and if the user has the same id.

    The usecase behind this constrain is that an user for example could
    be ldap wise in a group which could be addressed by two queries.

    :param user: userobject with user.login, user.realm

    :returns: array of resolvers, the user was found in
    """

    login = user.login
    realm = user.realm.lower() if user.realm else getDefaultRealm().lower()

    # calling the worker which stores resolver in the cache
    # but only if a resolver was found

    resolvers = get_resolvers_of_user(login, realm)

    if not resolvers:
        log.info("user %r not found in realm %r", login, realm)
        return []
    if "*" in login:
        return getResolvers(user)

    # -- ------------------------------------------------------------------ --
    # below we adjust the legacy stuff and put the resolver info into the user
    # -- ------------------------------------------------------------------ --
    resolver_match = []

    for resolver_spec in resolvers:
        # this is redundant but cached
        r_login, r_uid, r_user_info = lookup_user_in_resolver(
            login, None, resolver_spec
        )

        if not any((r_uid, r_user_info, r_login)):
            continue

        # this is redundant but cached
        _login, _uid, _user_info = lookup_user_in_resolver(
            login, r_uid, resolver_spec, user_info=r_user_info
        )

        _login, _uid, _user_info = lookup_user_in_resolver(
            None, r_uid, resolver_spec, user_info=r_user_info
        )

        y = getResolverObject(resolver_spec)
        resId = y.getResolverId()

        config_identifier = resolver_spec.rpartition(".")[-1]
        user.addResolverUId(
            resolver_spec, r_uid, config_identifier, resId, resolver_spec
        )
        resolver_match.append(resolver_spec)

    return resolver_match


def get_resolvers_of_user(login, realm):
    """
    get the resolvers of a given user, identified by loginname and realm
    """

    log.info("getting resolvers for user %r in realm %r", login, realm)

    def _get_resolvers_of_user(login=login, realm=realm):
        if not login:
            return []

        log.info("cache miss %r@%r", login, realm)
        Resolvers = []
        resolvers_of_realm = getRealms(realm).get(realm, {}).get("useridresolver", [])

        log.debug("check if user %r is in resolver %r", login, resolvers_of_realm)

        # Search for user in each resolver in the realm

        for resolver_spec in resolvers_of_realm:
            log.debug("checking in %r", resolver_spec)

            r_login, r_uid, r_user_info = lookup_user_in_resolver(
                login, None, resolver_spec
            )

            if not any((r_login, r_uid, r_user_info)):
                continue

            # now we optimize and feed the cache without calling the resolver
            # which is done by setting user_info not None

            lookup_user_in_resolver(login, r_uid, resolver_spec, user_info=r_user_info)

            lookup_user_in_resolver(None, r_uid, resolver_spec, user_info=r_user_info)

            Resolvers.append(resolver_spec)

        if not Resolvers:
            msg = f"no user {login!r} found in realm {realm!r}"
            raise NoResolverFound(msg)

        return Resolvers

    # ---------------------------------------------------------------------- --

    # we use a request local cache
    # - which is usefull especially if no persistant cache is enabled
    cache_key = json.dumps({"login": login, "realm": realm})

    if cache_key in request_context["UserRealmLookup"]:
        return request_context["UserRealmLookup"][cache_key]

    # ---------------------------------------------------------------------- --

    # if no caching is enabled, we just return the result of the inner func
    # otherwise we have to provide the partial function to the beaker cache

    try:
        resolvers_lookup_cache = _get_resolver_lookup_cache(realm)
        if resolvers_lookup_cache:
            p_get_resolvers_of_user = partial(
                _get_resolvers_of_user, login=login, realm=realm
            )

            Resolvers = resolvers_lookup_cache.get_value(
                key=cache_key, createfunc=p_get_resolvers_of_user
            )
        else:
            Resolvers = _get_resolvers_of_user(login=login, realm=realm)

    except NoResolverFound:
        log.info("No resolver found for user %r in realm %r", login, realm)
        return []

    except Exception as exx:
        log.error("unknown exception during resolver lookup")
        raise exx

    # ---------------------------------------------------------------------- --

    # fill in the result into the request local cache

    request_context["UserRealmLookup"][cache_key] = Resolvers

    # ---------------------------------------------------------------------- --

    log.debug("Found the user %r in %r", login, Resolvers)
    return Resolvers


def _get_resolver_lookup_cache(realm):
    """
    helper - common getter to access the user_lookup cache with scope realm
             to lookup if the user is in a realm

    :param realm: realm description
    :return: the resolver lookup cache
    """
    return get_cache(cache_name="user_lookup", scope=realm)


def delete_realm_resolver_cache(realmname):
    """
    in case of a resolver change / delete, we have to dump the cache
    """
    resolvers_lookup_cache = _get_resolver_lookup_cache(realmname)

    if resolvers_lookup_cache:
        resolvers_lookup_cache.clear()


def delete_from_realm_resolver_cache(login, realmname):
    """helper for realm cache cleanup"""

    resolvers_lookup_cache = _get_resolver_lookup_cache(realmname)

    if resolvers_lookup_cache:
        key = {"login": login, "realm": realmname}
        p_key = json.dumps(key)

        resolvers_lookup_cache.remove_value(key=p_key)


def delete_from_realm_resolver_local_cache(login, realmname):
    """helper for local realm cache cleanup"""

    key = {"login": login, "realm": realmname}
    p_key = json.dumps(key)

    if p_key in request_context["UserRealmLookup"]:
        del request_context["UserRealmLookup"][p_key]


def lookup_user_in_resolver(login, user_id, resolver_spec, user_info=None):
    """
    lookup login or uid in resolver to get userinfo

    :remark: the userinfo should not be part of this api and not be cached

    :param login: login name
    :param user_id: the users unique identifier
    :param resolver_spec: the resolver specifier
    :param user_info: optional parameter, required to fill the cache

    :return: login, uid, user info

    """

    log.debug(
        "User lookup for login %r or uid %r in resolver %r",
        login,
        user_id,
        resolver_spec,
    )

    def _lookup_user_in_resolver(login, user_id, resolver_spec, user_info=None):
        """
        this is the cache feeder function - it is called if an item is not
        found in the cache

        :remark: as the parameters are 'prepared' by func partial, the return
                 values must not overwrite the paramters with same name!

        :param login: login name
        :param user_id: the users uiniq identifier
        :param resolver_spec: the resolver specifier
        :paran user_info: optional parameter, required to fill the cache

        :return: login, uid, user info
        """

        if user_info:
            r_login = user_info["username"]
            r_user_id = user_info["userid"]
            return r_login, r_user_id, user_info

        if not resolver_spec:
            log.error("missing resolver spec %r", resolver_spec)
            msg = f"missing resolver spec {resolver_spec!r}"
            raise Exception(msg)

        y = getResolverObject(resolver_spec)

        if not y:
            log.error("[resolver with spec %r not found!]", resolver_spec)
            msg = f"Failed to access Resolver: {resolver_spec!r}"
            raise NoResolverFound(msg)

        if login:
            r_user_id = y.getUserId(login)
            if not r_user_id:
                log.error("Failed get user info for login %r", login)
                msg = f"Failed get user info for login {login!r}"
                raise NoResolverFound(msg)

            r_user_info = y.getUserInfo(r_user_id)
            return login, r_user_id, r_user_info

        elif user_id:
            r_user_info = y.getUserInfo(user_id)

            if not r_user_info:
                log.error("Failed get user info for user_id %r", user_id)
                msg = f"Failed get user info for user_id {user_id!r}"
                raise NoResolverFound(msg)

            r_login = r_user_info.get("username")
            return r_login, user_id, r_user_info

        else:
            log.error("neither user_id nor login id provided!")
            msg = "neither user_id nor login id provided!"
            raise NoResolverFound(msg)

    # ---------------------------------------------------------------------- --

    if isinstance(user_id, bytes):
        user_id = user_id.decode("utf-8")
    key = {"login": login, "user_id": user_id, "resolver_spec": resolver_spec}

    p_key = json.dumps(key)

    # --------------------------------------------------------------------- --

    # we use a request local cache
    # - which is especially usefull if no persistant cache is enabled

    if p_key in request_context["UserLookup"]:
        return request_context["UserLookup"][p_key]

    # --------------------------------------------------------------------- --

    # use the cache feeder or the direct call if no cache is defined

    user_lookup_cache = _get_user_lookup_cache(resolver_spec)

    try:
        if not user_lookup_cache:
            log.debug("lookup user without user lookup cache")

            result = _lookup_user_in_resolver(login, user_id, resolver_spec, user_info)

        else:
            log.debug("lookup user using the user lookup cache")

            p_lookup_user_in_resolver = partial(
                _lookup_user_in_resolver,
                login,
                user_id,
                resolver_spec,
                user_info,
            )

            result = user_lookup_cache.get_value(
                key=p_key, createfunc=p_lookup_user_in_resolver
            )

            # -------------------------------------------------------------- --

            # now check for cache consitancy:
            # if resolver + uid but different name, we delete the old entries

            if user_id is not None and resolver_spec:
                key2 = {
                    "login": None,
                    "user_id": user_id,
                    "resolver_spec": resolver_spec,
                }

                p_key2 = json.dumps(key2)

                p_lookup_user_in_resolver = partial(
                    _lookup_user_in_resolver,
                    None,
                    user_id,
                    resolver_spec,
                    user_info,
                )

                older_result = user_lookup_cache.get_value(
                    key=p_key2, createfunc=p_lookup_user_in_resolver
                )

                old_user_name = older_result[0]
                user_name = result[0]

                if old_user_name != user_name:
                    delete_from_user_cache(old_user_name, user_id, resolver_spec)

                    log.info("outdated entry deleted")

    except ResolverNotAvailable:
        log.error("unable to access the resolver")

        if not g.audit["action_detail"]:
            g.audit["action_detail"] = "Failed to connect to:"

        g.audit["action_detail"] += f"{resolver_spec}, "
        log.error("unable to connect to %r", resolver_spec)

        return None, None, None

    except NoResolverFound:
        log.info("user %r/%r not found in %r", login, user_id, resolver_spec)
        return None, None, None

    except Exception as exx:
        log.error("unknown exception during user lookup")
        raise exx

    # --------------------------------------------------------------------- --

    # preserve the user lookup result in the request local cache

    request_context["UserLookup"][p_key] = result

    # --------------------------------------------------------------------- --

    # we end up here if everything was okay

    log.debug("lookup done for %r: %r", p_key, result)
    return result


def _get_user_lookup_cache(resolver_spec):
    """
    helper - common getter to access the user_lookup cache with scope resolver
             to lookup if the user is in a resolver

    :param resolver_spec: resolver description
    :return: the user lookup cache
    """

    return get_cache("user_lookup", scope=resolver_spec)


def delete_resolver_user_cache(resolver_spec):
    """
    in case of a resolver change / delete, we have to dump the user cache
    """
    user_lookup_cache = _get_user_lookup_cache(resolver_spec)

    if user_lookup_cache:
        user_lookup_cache.clear()


def delete_from_local_cache(login, user_id, resolver_spec):
    """remove info from the request local cache"""

    key = {"login": login, "user_id": user_id, "resolver_spec": resolver_spec}

    p_key = json.dumps(key)

    if p_key in request_context["UserLookup"]:
        del request_context["UserLookup"][p_key]


def delete_from_resolver_user_cache(login, user_id, resolver_spec):
    """clean up the resolver cache"""

    user_lookup_cache = _get_user_lookup_cache(resolver_spec)

    if user_lookup_cache:
        key = {
            "login": login,
            "user_id": user_id,
            "resolver_spec": resolver_spec,
        }

        p_key = json.dumps(key)

        user_lookup_cache.remove_value(key=p_key)


def delete_from_user_cache(user_name, user_id, resolver_spec):
    """helper to remove permutation of user entry"""

    delete_from_resolver_user_cache(user_name, None, resolver_spec)

    delete_from_resolver_user_cache(None, user_id, resolver_spec)

    delete_from_resolver_user_cache(user_name, user_id, resolver_spec)

    # now cleanup the request local cache as well

    delete_from_local_cache(user_name, None, resolver_spec)

    delete_from_local_cache(None, user_id, resolver_spec)

    delete_from_local_cache(user_name, user_id, resolver_spec)


def getUserId(user, check_existance=False):
    """
    getUserId (userObject)

    :param user: user object
    :return: (uid,resId,resIdC)
    """

    uids = set()
    resId = None
    resolvers = getResolversOfUser(user)

    for resolver_spec in resolvers:
        _login, uid, _user_info = lookup_user_in_resolver(
            user.login, None, resolver_spec
        )

        # if none of the returns is truthy we have no result
        if not any((_login, uid, _user_info)):
            continue

        y = getResolverObject(resolver_spec)
        resId = y.getResolverId()

        # ------------------------------------------------------------------ --

        # the existance check makes a call to the resolver wo cache and checks
        # for the user info

        if check_existance:
            try:
                user_info = y.getUserInfo(uid)

            except ResolverNotAvailable:
                continue

            if not user_info:
                continue

            # -------------------------------------------------------------- --

            # with the "user existence" check, we gathered the user information
            # from the user resolver. We can now update the user cache by
            # deleting the current cache entry.

            realm = user.realm or getDefaultRealm()
            realm = realm.lower()

            delete_from_realm_resolver_cache(user.login, realm)
            delete_from_realm_resolver_local_cache(user.login, realm)

            delete_from_user_cache(user.login, uid, resolver_spec)

            # … and feeding the current user info back into the cache

            lookup_user_in_resolver(
                user_info["username"], uid, resolver_spec, user_info
            )

            lookup_user_in_resolver(
                user_info["username"], None, resolver_spec, user_info
            )

            # -------------------------------------------------------------- --

        uids.add(uid)
        user.resolverUid[resolver_spec] = uid

    if not uids:
        log.warning(
            "No uid found for the user >%r< in realm %r",
            user.login,
            user.realm,
        )

        msg = f"getUserId failed: no user >{user.login}< found!"
        raise UserError(msg, id=1205)

    if len(uids) > 1:
        log.warning(
            "multiple uid s found for the user >%r< in realm %r",
            user.login,
            user.realm,
        )

        msg = f"getUserId failed: multiple uids for user >{user.login}< found!"
        raise UserError(
            msg,
            id=1205,
        )

    return next(iter(uids)), resId, resolver_spec


def getSearchFields(user):
    searchFields = {}

    log.debug("[getSearchFields] entering function getSearchFields")

    for resolver_spec in getResolvers(user):
        """"""
        _cls_identifier, config_identifier = parse_resolver_spec(resolver_spec)

        if (
            len(user.resolver_config_identifier) > 0
            and config_identifier != user.resolver_config_identifier
        ):
            continue

        # try to load the UserIdResolver Class
        try:
            y = getResolverObject(resolver_spec)
            sf = y.getSearchFields()
            searchFields[resolver_spec] = sf

        except Exception as exx:
            log.warning("[getSearchField][ resolver spec %s: %r ]", resolver_spec, exx)
            continue

    return searchFields


def getUserList(param, search_user):
    users = []

    log.debug("[getUserList] entering function getUserList")

    # we have to recreate a new searchdict without the realm key
    # as delete does not work

    searchDict = {k: v for k, v in param.items() if k not in ("realm", "resConf")}
    log.debug("[getUserList] searchDict=%r", searchDict)

    resolverrrs = getResolvers(search_user)

    for resolver_spec in resolverrrs:
        cls_identifier, config_identifier = parse_resolver_spec(resolver_spec)

        if (
            len(search_user.resolver_config_identifier) > 0
            and config_identifier != search_user.resolver_config_identifier
        ):
            continue

        # try to load the UserIdResolver Class
        try:
            log.debug("[getUserList] Check for resolver: %r", resolver_spec)
            y = getResolverObject(resolver_spec)
            log.debug("[getUserList] with this search dictionary: %r ", searchDict)

            try:
                ulist_gen = y.getUserListIterator(searchDict)
                while True:
                    ulist = next(ulist_gen)
                    log.debug(
                        "[getUserList] setting the resolver <%r> for each user",
                        resolver_spec,
                    )
                    for u in ulist:
                        u["useridresolver"] = resolver_spec
                        _refresh_user_lookup_cache(u)
                    log.debug("[getUserList] Found this userlist: %r", ulist)
                    users.extend(ulist)

            except StopIteration:
                # we are done: all users are fetched or
                # page size limit reached
                pass

            except Exception as exc:
                log.info(
                    "Getting userlist using iterator not possible. "
                    "Falling back to fetching userlist without iterator. "
                    "Reason: %r",
                    exc,
                )
                ulist = y.getUserList(searchDict)
                for u in ulist:
                    u["useridresolver"] = resolver_spec

                    _refresh_user_lookup_cache(u)

                log.debug("[getUserList] Found this userlist: %r", ulist)
                users.extend(ulist)

        except KeyError as exx:
            log.error(
                "[getUserList][ resolver class identifier %s:%r ]",
                cls_identifier,
                exx,
            )
            raise exx

        except Exception as exx:
            log.error(
                "[getUserList][ resolver class identifier %s:%r ]",
                cls_identifier,
                exx,
            )
            continue

    return users


def getUserListIterators(param, search_user):
    """
    return a list of iterators for all userid resolvers

    :param param: request params (dict), which might be realm or resolver conf
    :param search_user: restrict the resolvers to those of the search_user
    """
    log.debug("Entering function getUserListIterator")

    user_iters = []
    searchDict = {k: v for k, v in param.items() if k not in ("realm", "resConf")}
    log.debug("searchDict %r", searchDict)

    resolverrrs = getResolvers(search_user)
    for resolver_spec in resolverrrs:
        cls_identifier, config_identifier = parse_resolver_spec(resolver_spec)

        if (
            len(search_user.resolver_config_identifier) > 0
            and config_identifier != search_user.resolver_config_identifier
        ):
            continue

        # try to load the UserIdResolver Class
        try:
            log.debug("Check for resolver: %r", resolver_spec)
            y = getResolverObject(resolver_spec)
            log.debug("With this search dictionary: %r ", searchDict)

            uit = (
                y.getUserListIterator(searchDict, limit_size=False)
                if hasattr(y, "getUserListIterator")
                else iter(y.getUserList(searchDict))
            )

            user_iters.append((uit, resolver_spec))

        except KeyError as exx:
            log.error("[ resolver class %r:%r ]", cls_identifier, exx)
            raise exx

        except Exception as exx:
            log.error("[ resolver class %r:%r ]", cls_identifier, exx)
            continue

    return user_iters


def getUserInfo(userid, resolver, resolver_spec):
    """
    get the user info for an given user, identified by the
    userid + resolver/resolver_spec

    :param userid: the unique user identifier
    :param resolver: the resolver (optional)
    :param resolver_spec: the resolver identifier + name
    :return: dictionary, which is empty, if no user info could be retreived
    """

    log.debug(
        "[getUserInfo] uid:%r resolver:%r class:%r",
        userid,
        resolver,
        resolver_spec,
    )

    if not userid:
        return {}

    _login, _user_id, userInfo = lookup_user_in_resolver(None, userid, resolver_spec)

    if not userInfo:
        return {}

    return userInfo


def getUserDetail(user):
    """
    Returns userinfo of an user

    :param user: the user
    :returns: the userinfo dict
    """
    (uid, resId, resClass) = getUserId(user)
    log.debug("got uid %r, ResId %r, Class %r", uid, resId, resClass)
    userinfo = getUserInfo(uid, resId, resClass)
    return userinfo


def getUserPhone(user, phone_type="phone"):
    """
    Returns the phone numer of a user

    :param user: the user with the phone
    :type user: user object

    :param phone_type: The type of the phone, i.e. either mobile or
                       phone (land line)
    :type phone_type: string

    :returns: list with phone numbers of this user object
    """
    (uid, resId, resClass) = getUserId(user)
    log.debug("[getUserPhone] got uid %r, ResId %r, Class %r", uid, resId, resClass)
    userinfo = getUserInfo(uid, resId, resClass)
    if phone_type in userinfo:
        log.debug(
            "[getUserPhone] got user phone %r of type %r",
            userinfo[phone_type],
            phone_type,
        )
        return userinfo[phone_type]
    else:
        log.warning(
            "[getUserPhone] userobject (%r,%r,%r) has no phone of type %r.",
            uid,
            resId,
            resClass,
            phone_type,
        )
        return ""


def get_authenticated_user(
    username, realm, password=None, realm_box=False, options=None
):
    """
    check the username and password against a userstore.

    remark: the method is used for auto_enrollToken/auto_assignToken

    :param username: the user login name
    :param realm: the realm, where the user belongs to
    :param password: the to be checked userstore password
    :param realm_box: take the information, if realmbox is displayed

    :return: None or authenticated user object
    """

    log.info(
        "User %r from realm %r tries to authenticate to selfservice",
        username,
        realm,
    )

    if not isinstance(username, str):
        username = username.decode(ENCODING)

    # ease the handling of options
    if not options:
        options = {}

    users = []
    uid = None

    # if we have an realmbox, we take the user as it is
    # - the realm is always given
    # - appended realms result in error
    if realm_box or realm:
        user = User(username, realm, "")
        users.append(user)
    else:
        def_realm = options.get("defaultRealm", getDefaultRealm())
        if def_realm:
            user = User(username, def_realm, "")
            users.append(user)
        if "@" in username:
            u_name, u_realm = username.rsplit("@", 1)
            user = User(u_name, u_realm, "")
            users.append(user)

    # Authenticate user
    auth_user = None
    found_uid = None

    for user in users:
        username = user.login
        realm = user.realm

        for resolver_spec in getResolversOfUser(user):
            login, uid, _user_info = lookup_user_in_resolver(
                user.login, None, resolver_spec
            )

            if not any((login, uid, _user_info)):
                continue

            if found_uid and uid != found_uid:
                msg = "user login %r : missmatch for userid: %r:%r"
                raise Exception(
                    msg,
                    user.login,
                    found_uid,
                    uid,
                )

            auth = False
            y = getResolverObject(resolver_spec)
            try:
                auth = y.checkPass(uid, password)
            except NotImplementedError as exx:
                log.info("user %r failed to authenticate.%r", login, exx)
                continue

            if auth:
                log.debug("Successfully authenticated user %r.", username)
            else:
                log.info("user %r failed to authenticate.", username)
                if found_uid:
                    msg = "previous authenticated user mismatch - password missmatch!"
                    raise Exception(msg)
                continue

            # add the fully qualified resolver to the resolver list
            user.resolvers_list.append(resolver_spec)

            if not found_uid:
                found_uid = uid

            auth_user = user

    if not auth_user:
        log.error("Error while trying to verify the username: %s", username)

    return auth_user


def _refresh_user_lookup_cache(user_dict):
    """
    Call this when you look up a user, e.g. when iterating over a list of
    users, in order to refresh the cache. The user_dict is the dictionary
    representation returned via UserList or UserListIterator, but make sure to
    set its "useridresolver" entry first to the resolver where the user was
    retrieved from.
    """
    lookup_user_in_resolver(
        user_dict.get("username"),
        None,
        user_dict["useridresolver"],
        user_info=user_dict,
    )
    lookup_user_in_resolver(
        None,
        user_dict.get("userid"),
        user_dict["useridresolver"],
        user_info=user_dict,
    )


# eof ---------------------------------------------------------------------- --
