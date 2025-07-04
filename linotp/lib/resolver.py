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
"""resolver objects and processing"""

import json
import logging
import re
from functools import partial

from flask import current_app

import linotp
from linotp.lib.cache import get_cache
from linotp.lib.config import getLinotpConfig, removeFromConfig, storeConfig
from linotp.lib.config.parsing import ConfigNotRecognized, ConfigTree
from linotp.lib.context import request_context as context
from linotp.lib.crypto.encrypted_data import EncryptedData
from linotp.lib.realm import getRealms
from linotp.lib.type_utils import boolean
from linotp.model.resolver import Resolver
from linotp.useridresolver import resolver_registry
from linotp.useridresolver.UserIdResolver import ResolverNotAvailable


class DeleteForbiddenError(Exception):
    pass


# -------------------------------------------------------------------------- --

# on module load integrate the parser function for resolver config
# into the ConfigTree class


def parse_resolver(composite_key, value):
    """Parses resolver data from a config entry"""

    attr_updates = {}

    # due to ambiguity of the second part in the config dot notation
    # we must check if the second part is a primary class identifier
    # of a resolver.

    cls_identifiers = get_resolver_types()  # ldapresolver, passwdresolver, etc

    for cls_identifier in cls_identifiers:
        if composite_key.startswith(f"linotp.{cls_identifier}."):
            break
    else:
        raise ConfigNotRecognized(composite_key)

    attr_updates["cls_identifier"] = cls_identifier

    # ------------------------------------------------------------------------ -

    parts = composite_key.split(".", 3)

    if len(parts) < 3:
        raise ConfigNotRecognized(
            composite_key,
            "This legacy resolver description is not supported anymore.",
        )
    # ------------------------------------------------------------------------ -

    attr_name = parts[2]
    attr_updates[attr_name] = value

    object_id = parts[3]  # the resolver name

    # ------------------------------------------------------------------------ -

    return object_id, attr_updates


ConfigTree.add_parser("resolvers", parse_resolver)

# -------------------------------------------------------------------------- --

__all__ = [
    "closeResolvers",
    "defineResolver",
    "deleteResolver",
    "getResolverInfo",
    "getResolverList",
    "getResolverObject",
    "initResolvers",
    "parse_resolver_spec",
    "setupResolvers",
]

# -------------------------------------------------------------------------- --

# for the the resolver name check we use a reqular expression

resolver_name_pattern = re.compile(r"^[a-zA-Z0-9_\-]{4,}$")


log = logging.getLogger(__name__)


def save_resolver_config(resolver, config, prefix, name):
    """
    save the processed config to the global linotp config and to the db

    """

    res = True

    for key, value in list(config.items()):
        # if the config contains something starting with 'linotp.'
        # it does not belong to the resolver rather then to linotp

        if key.startswith("linotp."):
            continue

        # Construct the fully qualified key name
        full_key = f"{prefix}.{key}.{name}"

        # do some type naming
        typ = "unknown"
        if key in resolver.resolver_parameters:
            (_req, _def, data_typ) = resolver.resolver_parameters.get(key)
            try:
                typ = data_typ.__name__
            except Exception as _exx:
                log.error("unknown data type for %s", key)

        res = storeConfig(full_key, value, typ=typ)

    return res


def defineResolver(params):
    """
    set up a new resolver from request parameters

    the setup of the resolver includes the loading of the resolver config.
    this is required to allow the resolver to check if all required parameters
    are available.

    As the resolver (for historical reasons) has access to the overall LinOTP
    config, we have to prepare the resolver definition, which is done by the
    Resolver() class. Thus during the defineResolver, we have first to merge
    the LinOTP config with the new resolver config (from the params) and if the
    loading of the config went well, we will do the saving of the resolver.

    :param params: dict of request parameters
    """

    typ = params["type"]
    conf = params["name"]

    if not resolver_name_pattern.match(conf):
        msg = (
            "Resolver name is invalid. It may contain characters, "
            "numbers, underscore (_), hyphen (-)! %r"
        )
        raise Exception(
            msg,
            conf,
        )

    resolver_cls = get_resolver_class(typ)

    if not resolver_cls:
        msg = f"no such resolver type '{typ!r}' defined!"
        raise Exception(msg)

    # ---------------------------------------------------------------------- --

    #
    # for defining the resolver, we have to merge the linotp config,
    # which contains:
    #
    # * the previous entries for this definition and
    # * the global config entries like linotp.use_system_certs
    #
    # with the provided parameters.
    #

    p_config, _missing = resolver_cls.filter_config(context["Config"])

    l_config, _missing = resolver_cls.filter_config(params)

    p_config.update(l_config)

    # ---------------------------------------------------------------------- --

    # finally we test the loading of config, which will raise an exception
    # if something is missing

    resolver = resolver_cls()

    resolver.loadConfig(p_config, conf)

    if resolver is None:
        return False

    # ---------------------------------------------------------------------- --

    #
    # if all went fine we finally save the config and
    # in case of an update, flush the cache

    save_resolver_config(resolver, p_config, prefix="linotp." + typ, name=conf)

    resolver_spec = f"{resolver.__module__}.{resolver.__class__.__name__}.{conf}"

    _flush_user_resolver_cache(resolver_spec)

    return resolver


def get_cls_identifier(config_identifier):
    """
    Returns the class identifier string for a existing resolver
    identified by config_identifier (or None, if config_identifier
    doesn't exist)
    """

    config = context.get("Config")
    cls_identifiers = resolver_registry.keys()

    for config_entry in config:
        if not config_entry.endswith(config_identifier):
            continue

        for cls_identifier in cls_identifiers:
            if config_entry.startswith(f"linotp.{cls_identifier}"):
                return cls_identifier

    return None


def get_admin_resolvers():
    """ """
    admin_realm_name = current_app.config["ADMIN_REALM_NAME"].lower()

    admin_realm_definition = getRealms(admin_realm_name).get(admin_realm_name, {})

    if not admin_realm_definition:
        return []

    admin_resolvers = set()
    for resolver_spec in admin_realm_definition["useridresolver"]:
        admin_resolvers.add(resolver_spec.rpartition(".")[2])

    return list(admin_resolvers)


# external system/getResolvers
def getResolverList(filter_resolver_type=None, config=None):
    """
    Gets the list of configured resolvers

    :param filter_resolver_type: Only resolvers of the given type are returned
    :type filter_resolver_type: string
    :rtype: Dictionary of the resolvers and their configuration
    """
    resolvers = {}
    resolvertypes = get_resolver_types()
    local_admin_resolver = current_app.config["ADMIN_RESOLVER_NAME"]
    admin_resolvers = get_admin_resolvers()
    conf = config or context.get("Config")

    for entry in conf:
        for resolver_type in resolvertypes:
            if entry.startswith(f"linotp.{resolver_type}") and (
                filter_resolver_type is None or filter_resolver_type == resolver_type
            ):
                # the resolver might contain dots "." so take
                # all after the 3rd dot for the resolver name
                resolver = entry.split(".", 3)
                # An old entry without resolver name
                if len(resolver) <= 3:
                    break
                # this is a patch for a hack:
                #
                # as entry, the first found resolver is shown
                # as the PasswdResolver only has one entry, this always
                # has been 'fileName', which now as could be 'readonly'
                # thus we skip the readonly entry:
                if resolver[2] == "readonly":
                    continue

                resolver_name = resolver[3]
                resolver_info = {
                    "resolvername": resolver_name,
                    "entry": entry,
                    "type": resolver_type,
                    "spec": f"{get_resolver_class(resolver_type).db_prefix}.{resolver_name}",
                    "admin": resolver_name in admin_resolvers,
                    "immutable": local_admin_resolver == resolver_name,
                }

                readonly_entry = f"{resolver[0]}.{resolver[1]}.readonly.{resolver_name}"
                if readonly_entry in conf:
                    try:
                        if boolean(conf[readonly_entry]):
                            resolver_info["readonly"] = True
                    except Exception as _exx:
                        log.info(
                            "Failed to convert 'readonly' attribute %r:%r",
                            readonly_entry,
                            conf[readonly_entry],
                        )

                resolvers[resolver_name] = resolver_info
                # Dont check the other resolver types
                break

    return resolvers


def getResolverInfo(resolvername, passwords=False):
    """
    return the resolver info of the given resolvername

    :param resolvername: the requested resolver
    :type  resolvername: string

    :return : dict of resolver description
    """

    result = {"type": None, "data": {}, "resolver": resolvername}

    linotp_config = context.get("Config")
    resolver_types = get_resolver_types()

    local_admin_resolver = current_app.config["ADMIN_RESOLVER_NAME"]

    # --------------------------------------------------------------------- --

    # lookup, which resolver type is associated with this resolver name

    for config_entry in linotp_config:
        if config_entry.endswith("." + resolvername):
            # check if this is a resolver definition, starting with linotp.
            # and continuing with a resolver type

            part = config_entry.split(".")

            if len(part) > 3 and part[0] == "linotp" and part[1] in resolver_types:
                resolver_type = part[1]
                break

    else:
        return result

    # now we can load the resolver config unsing the resolver class

    resolver_cls = get_resolver_class(resolver_type)

    if resolver_cls is None:
        msg = f"no such resolver type '{resolver_type!r}' defined!"
        raise Exception(msg)

    result["spec"] = resolver_cls.db_prefix + "." + resolvername

    res_conf, _missing = resolver_cls.filter_config(linotp_config, resolvername)
    # suppress global config entries
    res_conf = {k: v for k, v in res_conf.items() if not k.startswith("linotp.")}
    # --------------------------------------------------------------------- --

    # now prepare the resolver config output, which should contain
    #
    # - no global entries, starting with 'linotp.'
    # - adjusted passwords
    # - all values as text
    for key, value in res_conf.items():
        # should passwords be displayed?
        if key in resolver_cls.crypted_parameters:
            # we have to be sure that we only have encrypted data objects for
            # secret data
            if not isinstance(value, EncryptedData):
                msg = "Encrypted Data Object expected"
                raise Exception(msg)

            # if parameter password is True, we need to unencrypt
            if passwords:
                res_conf[key] = value.get_unencrypted()

        # as we have in the resolver config typed values, this might
        # lead to some trouble. so we prepare for output comparison
        # the string representation

        if not isinstance(value, str):
            res_conf[key] = f"{value!r}"

    if "readonly" in res_conf:
        try:
            result["readonly"] = boolean(res_conf["readonly"])
        except Exception:
            log.info(
                "Failed to convert 'readonly' attribute %r:%r",
                resolvername,
                res_conf["readonly"],
            )

    result["type"] = resolver_type
    result["data"] = res_conf
    result["admin"] = resolvername in get_admin_resolvers()

    # set the immutable flag if its the local_admin_resolver
    result["immutable"] = local_admin_resolver == resolvername

    return result


def deleteResolver(resolvername):
    """
    delete a resolver and all related config entries

    :paramm resolvername: the name of the to be deleted resolver
    :type   resolvername: string
    :return: sucess or fail
    :rtype:  boolean

    """

    if resolvername == current_app.config["ADMIN_RESOLVER_NAME"]:
        msg = f"default admin resolver {resolvername} is not allowed to be removed!"
        raise DeleteForbiddenError(msg)

    resolvertypes = get_resolver_types()
    conf = context.get("Config")

    del_entries = []
    resolver_specs = set()

    for entry in conf:
        rest = entry.split(".", 3)
        if len(rest) > 3 and rest[-1] == resolvername:
            typ = rest[1]
            if rest[0] in ("linotp", "enclinotp") and typ in resolvertypes:
                del_entries.append(entry)
                resolver_conf = get_resolver_class_config(typ)
                resolver_class = resolver_conf.get(typ, {}).get("clazz")
                fqn = f"{resolver_class}.{resolvername}"
                resolver_specs.add(fqn)

    if del_entries:
        try:
            for entry in del_entries:
                removeFromConfig(entry)
        except Exception as exx:
            log.error(
                "Deleting resolver %s failed. Exception was %r",
                resolvername,
                exx,
            )
            return False

        # on success we can flush the caches
        for resolver_spec in resolver_specs:
            _flush_user_resolver_cache(resolver_spec)
            _delete_from_resolver_config_cache(resolver_spec)
        return True

    return False


def getResolverObjectByName(resolver_name: str):
    resolver_spec = getResolverSpecByName(resolver_name)
    return getResolverObject(resolver_spec)


def getResolverSpecByName(resolver_name):
    resolver_dict = getResolverDictByName(resolver_name)
    return resolver_dict["spec"]


def getResolverDictByName(resolver_name):
    resolvers_dict = getResolverList()
    try:
        return resolvers_dict[resolver_name]
    except KeyError as exx:
        message = f"Could not find a resolver with this name: {resolver_name}"
        raise linotp.lib.user.NoResolverFound(message) from exx


# external in token.py user.py validate.py
def getResolverObject(resolver_spec, config=None, load_config=True):
    """
    get the resolver instance from a resolver specification.

    :remark: internally this function uses the request context for caching.

    :param resolver_spec: the resolver string as from the token including
                          the config identifier.

                          format:
                          <resolver class identifier>.<config identifier>

    :return: instance of the resolver with the loaded config (or None
             if specification was invalid or didn't match a resolver)

    """

    #  this patch is a bit hacky:
    # the normal request has a request context, where it retrieves
    # the resolver info from and preserves the loaded resolvers for reusage
    # But in case of a authentication request (by a redirect from a 401)
    # the caller is no std request and the context object is missing :-(
    # The solution is to deal with local references, either to the
    # global context or to local data (where we have no reuse of the resolver)

    resolvers_loaded = context.setdefault("resolvers_loaded", {})

    if not config:
        config = getLinotpConfig()

    # test if the resolver is in the cache
    if resolver_spec in resolvers_loaded:
        return resolvers_loaded.get(resolver_spec)

    # no resolver - so instantiate one
    else:
        cls_identifier, config_identifier = parse_resolver_spec(resolver_spec)

        if not cls_identifier or not config_identifier:
            log.error(
                "Format error: resolver_spec must have the format "
                "<resolver_class_identifier>.<config_identifier>, but "
                "value was %r",
                resolver_spec,
            )
            return None

        resolver_cls = get_resolver_class(cls_identifier)

        if resolver_cls is None:
            log.error("Unknown resolver class: %r", cls_identifier)
            return None

        resolver = resolver_cls()

        if load_config:
            try:
                resolver.loadConfig(config, config_identifier)

            except ResolverNotAvailable:
                log.error("Unable to connect to resolver %r", resolver_spec)
                return None

            except Exception as exx:
                # FIXME: Except clause is too general. resolver
                # should be ResolverLoadConfigError
                # exceptions in the useridresolver modules should
                # have their own type, so we can filter here
                log.error(
                    "Resolver config loading failed for resolver with "
                    "specification %s: %r",
                    resolver_spec,
                    exx,
                )

                return None

            # in case of the replication there might by difference
            # in the used resolver config and the config from the LinOTP config
            _check_for_resolver_cache_flush(resolver_spec, config_identifier)

            resolvers_loaded[resolver_spec] = resolver

        return resolver


def _check_for_resolver_cache_flush(resolver_spec, config_identifier):
    """
    check if the current resolver config is still the current one

    this is done by using as well the caching with a dedicated cache
    that holds the former configuration. If the current config does not match
    the retrieved value, the cache is out dated and we have to flush the
    related caches

    :param resolver_spec: resolver spec - fully qualified resolver
    :param config_identifier: the resolver config identifier
    """

    resolver_config = _get_resolver_config(config_identifier)
    resolver_config_dump = json.dumps(resolver_config)

    res_conf_hash = _lookup_resolver_config(resolver_spec, resolver_config)

    if res_conf_hash != resolver_config_dump:
        # now we delete the user_resolver cache
        _flush_user_resolver_cache(resolver_spec)

        # and establish the new config in the resolver config cache
        # by deleting the reference key and adding the entry

        _delete_from_resolver_config_cache(resolver_spec)
        _lookup_resolver_config(resolver_spec, resolver_config)


def _flush_user_resolver_cache(resolver_spec):
    """
    flush the user realm cache
        in case of a change of the resolver, all realms which use
        this resolver must be flushed

    :param resolver_spec: the resolve which has been updated
    :return: - nothing -
    """

    from linotp.lib.user import (  # noqa: PLC0415
        delete_realm_resolver_cache,
        delete_resolver_user_cache,
    )

    delete_resolver_user_cache(resolver_spec)

    config = context["Config"]
    realms = config.getRealms()

    # if a resolver is redefined, we have to refresh the related realm cache
    for realm_name, realm_spec in list(realms.items()):
        if resolver_spec in realm_spec.get("useridresolver", []):
            delete_realm_resolver_cache(realm_name)


def _get_resolver_config(resolver_config_identifier):
    """
    get the resolver config of a resolver identified by its config identifier
        helper to access the resolver configuration

    :param resolver_config_identifier: resolver config identifier as string
    :return: dict with the resolver configuration
    """

    # identify the fully qualified resolver spec by all possible resolver
    # prefixes, which are taken from the resolver_classes list
    lookup_keys = [f"linotp.{entry}" for entry in resolver_registry]

    # we got the resolver prefix, now we can search in the config for
    # all resolver configuration entries
    resolver_config = {
        key: value
        for key, value in context["Config"].items()
        if key.endswith(resolver_config_identifier)
        and any(key.startswith(entry) for entry in lookup_keys)
    }
    return resolver_config


# -- -------------------------------------------------------------------- --


def _lookup_resolver_config(resolver_spec, resolver_config=None):
    """
    lookup resolver configuration for a given resolver spec

    :param resolver_spec: resolver specification (full qualified)
    :param resolver_config: used for cache filling

    :return: resolver configuration as dict
    """

    def __lookup_resolver_config(resolver_spec, resolver_config=None):
        """
        inner function which is called on a cache miss

        :param resolver_spec: resolver specification (full qualified)
        :param resolver_config: used for cache filling

        :return: resolver configuration as dict

        """
        if resolver_config:
            return json.dumps(resolver_config)

        return None

    # get the resolver configuration cache, if any
    resolver_config_cache = _get_resolver_config_cache()
    if not resolver_config_cache:
        return __lookup_resolver_config(resolver_spec, resolver_config)

    # define the cache lookup function as partial as the standard
    # beaker cache manager does not support arguments
    # for the inner cache function
    p_lookup_resolver_config = partial(
        __lookup_resolver_config, resolver_spec, resolver_config
    )

    p_key = resolver_spec

    # retrieve config from the cache, accessed by the p_key
    conf_hash = resolver_config_cache.get_value(
        key=p_key,
        createfunc=p_lookup_resolver_config,
    )

    return conf_hash


def _get_resolver_config_cache():
    """
    helper - common getter to access the resolver_config cache

    the resolver config cache is used to track the resolver configuration
    changes. therefore for each resolver spec the resolver config is stored
    in a cache. In case of an request the comparison of the resolver config
    with the cache value is made and in case of inconsistancy the resolver
    user cache is flushed.

    :remark: This cache is only enabled, if the resolver user lookup cache
             is enabled too

    :return: the resolver config cache
    """

    return get_cache(cache_name="resolver_lookup")


def _delete_from_resolver_config_cache(resolver_spec):
    """
    delete one entry from the resolver config lookup cache
    :param resolver_spec: the resolver spec (fully qualified)
    :return: - nothing -
    """
    resolver_config_cache = _get_resolver_config_cache()
    if resolver_config_cache:
        resolver_config_cache.remove_value(key=resolver_spec)


# external lib/base.py
def setupResolvers(config=None, cache_dir="/tmp"):
    """
    hook at the server start to initialize the resolvers classes
    - the resolver class setup should only be called once

    :param config: the linotp config
    :param cache_dir: the cache directory, which could be used in each resolver

    :return: -nothing-
    """
    # resolver classes can have multiple aliases, hence can contain duplicates.
    # so we remove them:
    unique_resolver_classes = set(resolver_registry.values())

    for resolver_cls in unique_resolver_classes:
        if not hasattr(resolver_cls, "setup") or hasattr(resolver_cls, "_setup_done"):
            continue

        try:
            resolver_cls.setup(config=config, cache_dir=cache_dir)
            resolver_cls._setup_done = True
        except Exception as exx:
            log.error(
                "Resolver setup: Failed to call setup of %r. Exception was %r",
                resolver_cls,
                exx,
            )


def initResolvers():
    """
    hook for the request start -
        create  a deep copy of the dict with the global resolver classes
    """
    try:
        # dict of all resolvers, which are instantiated during the request
        context["resolvers_loaded"] = {}

    except Exception as exx:
        log.error(
            "Failed to initialize resolver for context. Exception was %r",
            exx,
        )
    return context


# external lib/base.py
def closeResolvers():
    """
    hook to close the resolvers at the end of the request
    """
    try:
        for resolver in context.get("resolvers_loaded", {}).values():
            if hasattr(resolver, "close"):
                resolver.close()
    except Exception as exx:
        log.error("Failed to close resolver in context. Error was %r", exx)


def getResolverClassName(cls_identifier, resolver_name):
    """
    Constructs a database identifier for a specific
    resolver by concatenating the database prefix
    with the resolver_name

    :param cls_identifier: The identifier for the resolver
        class (as defined in the registry)

    :param resolver_name: The name of the resolver
    """

    db_prefix = get_resolver_db_prefix(cls_identifier)

    if db_prefix is None:
        return ""

    return f"{db_prefix}.{resolver_name}"


def get_resolver_db_prefix(cls_identifier):
    """
    Returns the database prefix used in the user column
    for a given resolver class identifier

    :param cls_identifier: The identifier for the resolver
        class (as defined in the registry)
    """

    resolver_cls = get_resolver_class(cls_identifier)

    if resolver_cls is None:
        return None

    return resolver_cls.db_prefix


# internal functions
def get_resolver_class(cls_identifier):
    """
    return the class object for a resolver type
    :param resolver_type: string specifying the resolver
                          fully qualified or abreviated
    :return: resolver object class
    """

    return resolver_registry.get(cls_identifier)


def get_resolver_types():
    """
    get the array of the registred resolvers

    :return: array of resolvertypes like 'passwdresolver'
    """
    types = [
        resolver_cls.getResolverClassType()
        for resolver_cls in resolver_registry.values()
    ]
    return types


def get_resolver_class_config(claszzesType):
    """
    get the configuration description of a resolver

    :param claszzesType: literal resolver type
    :return: configuration description dict
    """
    descriptor = None
    resolver_class = get_resolver_class(claszzesType)

    if resolver_class is not None:
        descriptor = resolver_class.getResolverClassDescriptor()

    return descriptor


def parse_resolver_spec(resolver_spec):
    """
    expects a resolver specification and returns a tuple
    containing the resolver class identifier and the config
    identifier

    :param resolver_spec: a resolver specification

                          format:
                          <resolver class identifier>.<config identifier>

    :return: (cls_identifier, config_identifier)

    """

    cls_identifier, _sep, config_identifier = resolver_spec.rpartition(".")
    return cls_identifier, config_identifier


def prepare_resolver_parameter(new_resolver_name, param, previous_name=None):
    """
    prepare the create/update/rename of a resolver
    used in system/setResolver and admin/testresolver

    :param new_resolver_name: the name of the new/current resolver
    :param param: the new set of parameters
    :param previous_name: the previous name of the resolver

    :return: tuple of set of potential extended parameters and
             the list of the missing parameters
    """
    primary_key_changed = False

    resolver_cls = get_resolver_class(param["type"])

    if resolver_cls is None:
        msg = "no such resolver type '{!r}' defined!".format(param["type"])
        raise Exception(msg)

    # for rename and update, we support the merge with previous parameters
    if previous_name:
        # get the parameters of the previous resolver
        previous_resolver = getResolverInfo(previous_name, passwords=True)

        previous_param = previous_resolver["data"]
        previous_readonly = boolean(previous_resolver.get("readonly", False))

        # get the critical parameters for this resolver type
        # and check if these parameters have changed

        is_critical = resolver_cls.is_change_critical(
            new_params=param, previous_params=previous_param
        )

        # if there are no critical changes, we can transfer
        # the encrypted parameters from previous resolver

        if not is_critical:
            merged_params = resolver_cls.merge_crypted_parameters(
                new_params=param, previous_params=previous_param
            )

            param.update(merged_params)

        # in case of a readonly resolver, no changes beneath a rename
        # is allowed

        if previous_readonly:
            for key, p_value in previous_param.items():
                # we inherit the readonly parameter if it is
                # not provided by the ui
                if key == "readonly":
                    param["readonly"] = boolean(p_value)
                elif p_value != param.get(key, ""):
                    msg = "Readonly Resolver Change not allowed!"
                    raise Exception(msg)

        # check if the primary key changed - if so, we need
        # to migrate the resolver

        primary_key_changed = resolver_cls.primary_key_changed(
            new_params=param, previous_params=previous_param
        )

    # ---------------------------------------------------------- --

    # check if all crypted parameters are included

    missing = resolver_cls.missing_crypted_parameters(param)

    return param, missing, primary_key_changed


def get_resolver(resolver_name: str):
    resolver_dict = getResolverDictByName(resolver_name)
    return Resolver.from_dict(resolver_dict)


def get_resolvers():
    return [
        Resolver.from_dict(resolver_dict)
        for resolver_dict in getResolverList().values()
    ]
