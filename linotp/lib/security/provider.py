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
The security provider is a dynamic handler for security relevant tasks like
random, crypt, decrypt, sign
"""

import _thread
import logging
import time

from linotp.lib.error import HSMException
from linotp.lib.rw_lock import RWLock
from linotp.lib.security import FatalHSMException

DEFAULT_KEY = 0
CONFIG_KEY = 1
TOKEN_KEY = 2
VALUE_KEY = 3


log = logging.getLogger(__name__)


class SecurityProvider:
    """
    the security provider is the singleton in the server who provides
    the security modules to run security relevant methods

    - read the hsm configurations
    - set up a pool of hsm modules
    - bind a hsm to one session
    - free the hsm from session after usage

    the thread id is used as session identifier
    """

    def __init__(self):
        """
        setup the security provider, which is called on server startup
        from the flask app init

        :param secLock: RWLock() to support server wide locking
        :type  secLock: RWLock

        :return: -

        """
        self.config = {}
        self.security_modules = {}
        self.activeOne = "default"
        self.hsmpool = {}
        self.rwLock = RWLock()
        self.max_retry = 5

    def load_config(self, config):
        """
        load the security modules configuration
        """

        try:
            security_provider = config.get("ACTIVE_SECURITY_MODULE", "default")
            # self.active one is legacy.. therefore we set it here
            self.activeOne = security_provider
            log.debug(
                "[SecurityProvider:load_config] setting active security module: %s",
                self.activeOne,
            )

            # add active provider config to self.config with the active
            # provider as key and the config dict as value
            if self.activeOne == "default":
                default_security_provider_config = config.get("HSM_DEFAULT_CONFIG")
                keyFile = config["SECRET_FILE"]
                default_security_provider_config["file"] = keyFile
                security_provider_config = {"default": default_security_provider_config}
                self.config.update(security_provider_config)

            if self.activeOne == "pkcs11":
                security_provider_config = {"pkcs11": config.get("HSM_PKCS11_CONFIG")}
                self.config.update(security_provider_config)

        except Exception as exx:
            log.error("[load_config] failed to identify module")
            error = f"failed to identify module: {exx!r} "
            raise HSMException(error, id=707) from exx

        # now create a pool of hsm objects for each module
        self.rwLock.acquire_write()
        try:
            for id in self.config:
                self.createHSMPool(id)
        finally:
            self.rwLock.release()

    def loadSecurityModule(self, module_id=None):
        """
        return the specified security module

        :param id:  identifier for the security module (from the configuration)
        :type  id:  String or None

        :return:    None or the created object
        :rtype:     security module
        """

        ret = None

        if module_id is None:
            module_id = self.activeOne

        if module_id not in self.config:
            return ret

        config = self.config.get(module_id)
        if "module" not in config:
            return ret

        module = config.get("module")
        methods = ["encrypt", "decrypt", "random", "setup_module"]
        method = ""

        parts = module.split(".")
        className = parts[-1]
        packageName = ".".join(parts[:-1])

        mod = __import__(packageName, globals(), locals(), [className], 0)
        klass = getattr(mod, className)
        config_name = klass.getAdditionalClassConfig()
        additional_config = self.get_config_entries(config_name)

        for method in methods:
            if hasattr(klass, method) is False:
                error = (
                    f"[loadSecurityModule] Security Module {module!r} misses the "
                    f"following interface: {method!r}"
                )
                log.error(error)
                raise NameError(error)

        ret = klass(config, add_conf=additional_config)
        self.security_modules[module_id] = ret
        return ret

    def get_config_entries(self, config_name):
        """
        :param names: list of config entries by modulename
        :return: dict
        """
        merged_config = {}

        for provider, provider_config in list(self.config.items()):
            module = provider_config.get("module")
            provider_class = module.split(".")[-1]
            if provider_class in config_name:
                merged_config = self.config[provider]

        return merged_config

    def _getHsmPool_(self, hsm_id):
        ret = None
        if hsm_id in self.hsmpool:
            ret = self.hsmpool.get(hsm_id)
        return ret

    def setupModule(self, hsm_id, config=None):
        """
        setupModule is called during runtime to define
        the config parameters like password or connection strings
        """
        self.rwLock.acquire_write()
        try:
            pool = self._getHsmPool_(hsm_id)
            if pool is None:
                error = f"[setupModule] failed to retieve pool for hsm_id: {hsm_id!r}"
                log.error(error)
                raise HSMException(error, id=707)

            for entry in pool:
                hsm = entry.get("obj")
                hsm.setup_module(config)

            self.activeOne = hsm_id
        except Exception as exx:
            error = f"[setupModule] failed to load hsm : {exx!r}"
            log.error(error)
            raise HSMException(error, id=707) from exx

        finally:
            self.rwLock.release()
        return self.activeOne

    def createHSMPool(self, hsm_id=None, *args, **kw):
        """
        Setup the pool of security module connections

        :param hsm_id: The id of the hsm provider which must exist in the hsm config,
        if None the one from the config will be used

        :return: The created pool (list) of hsm connections

        """
        pool = None
        # amount has to be taken from the hsm-id config
        if hsm_id is None:
            provider_ids = self.config
        elif hsm_id in self.config:
            provider_ids = []
            provider_ids.append(hsm_id)
        else:
            error = f"[createHSMPool] failed to find hsm_id: {hsm_id!r}"
            log.error(error)
            raise HSMException(error, id=707)

        for id in provider_ids:
            pool = self._getHsmPool_(id)
            if pool is not None:
                log.debug("[createHSMPool] already got this pool: %r", pool)
                continue

            conf = self.config.get(id)
            size = int(conf.get("poolsize", 10))
            log.debug("[createHSMPool] creating pool %r with size=%r", id, size)

            pool = []
            for _i in range(size):
                error = ""
                hsm = None
                try:
                    hsm = self.loadSecurityModule(id)
                except FatalHSMException as exx:
                    log.error("[createHSMPool] %r %r ", id, exx)
                    if id == self.activeOne:
                        raise exx
                    error = f"{id!r}: {exx!r}"

                except Exception as exx:
                    log.error("[createHSMPool] %r ", exx)
                    error = f"{id!r}: {exx!r}"

                pool.append({"obj": hsm, "session": 0, "error": error})

            self.hsmpool[id] = pool
        return pool

    def _find_hsm_of_session(self, pool, sessionId):
        """
        Searches the hsm pool and finds the hsm connection allocated by the
        thread (sessionId)

        :param pool: The pool (list) of hsm connections to search in.
        :param sessionId: The thread id which the hsm connection should be allocated by.
        :return: the hsm connection found or None
        """
        found = None
        # find session
        for hsm in pool:
            hsession = hsm.get("session")
            if hsession == sessionId:
                found = hsm
        return found

    def _allocate_hsm_for_session(self, pool, sessionId):
        """
        Searches the pool for an un-allocated hsm connection and assigns it to
        the thread id (session)

        :param pool: The hsm pool (list) of connections to search in
        :param sessionId: Thread id that will be allocated to the found hsm

        :return: The found hsm from the pool

        """
        found = None
        for hsm in pool:
            hsession = hsm.get("session")
            if str(hsession) == "0":
                hsm["session"] = sessionId
                found = hsm
                break
        return found

    def _freeHSMSession(self, pool, sessionId):
        """
        Look in the pool and find the hsm connection which is allocated by
        the thread (sessionId) and make it free.

        :param pool: The hsm pool (list) of connections
        :param sessionId: the thread id for which the alllocated hsm connection
        should be freed

        :return: the free hsm connection
        """
        hsm = None
        for hsm in pool:
            hsession = hsm.get("session")
            if str(hsession) == str(sessionId):
                hsm["session"] = 0
                break
        return hsm

    def dropSecurityModule(self, hsm_id=None, sessionId=None):
        """
        Searches in the hsm pool and finds the hsm connection allocated by the
        thread (sessionId) and makes that hsm connection free

        :param hsm_id: the identifier of the hsm pool which is stated in the hsm config
        :param sessionId: the thread id

        :return: expected to be True if it succeeds to drop, false if it fails

        """

        result = None
        found = None
        if hsm_id is None:
            hsm_id = self.activeOne
        if sessionId is None:
            sessionId = str(_thread.get_ident())

        if hsm_id not in self.config:
            error = (
                "[SecurityProvider:dropSecurityModule] no config found "
                f"for hsm with id {hsm_id!r} "
            )
            log.error(error)
            raise HSMException(error, id=707)

        # find session
        try:
            pool = self._getHsmPool_(hsm_id)
            self.rwLock.acquire_write()
            found = self._find_hsm_of_session(pool, sessionId)

            if found is None:
                log.info(
                    "[SecurityProvider:dropSecurityModule] could not find "
                    "hsm connection allocated by thread in hsm pool: %r ",
                    hsm_id,
                )
            else:
                result = self._freeHSMSession(pool, sessionId)
        finally:
            self.rwLock.release()
        return result is not None

    def getSecurityModule(self, hsm_id=None, sessionId=None):
        """
        Allocate a security module for the sessionId

        :param hsm_id: Specifies from which pool to choose. It will use the
        activeOne if it's not specified
        :param sessionId: Specifies the threadId which will be used for the
        allocation of the hsm connection

        :return: The allocated hsm connection
        """
        found = None
        if hsm_id is None:
            hsm_id = self.activeOne
        if sessionId is None:
            sessionId = str(_thread.get_ident())

        if hsm_id not in self.config:
            error = (
                "[SecurityProvider:getSecurityModule] no config found for "
                f"hsm with id {hsm_id!r} "
            )
            log.error(error)
            raise HSMException(error, id=707)

        retry = True
        tries = 0
        locked = False

        while retry is True:
            try:
                pool = self._getHsmPool_(hsm_id)
                self.rwLock.acquire_write()
                locked = True
                # find session
                found = self._find_hsm_of_session(pool, sessionId)
                if found is not None:
                    # if session is ok - return
                    self.rwLock.release()
                    locked = False
                    retry = False
                    log.debug(
                        "[getSecurityModule] using existing pool session %s",
                        found,
                    )
                    return found
                else:
                    # create new entry
                    log.debug(
                        "[getSecurityModule] getting new session (id=%s) "
                        "from pool '%s'",
                        sessionId,
                        hsm_id,
                    )
                    found = self._allocate_hsm_for_session(pool, sessionId)
                    self.rwLock.release()
                    locked = False
                    if found is None:
                        tries += 1
                        delay = 1 + int(0.2 * tries)
                        log.warning(
                            "try %d: could not bind hsm to session  - "
                            "going to sleep for %r",
                            tries,
                            delay,
                        )
                        time.sleep(delay)
                        if tries >= self.max_retry:
                            error = (
                                f"[SecurityProvider:getSecurityModule] "
                                f"{tries} retries: could not bind hsm to "
                                f"session for {delay} seconds"
                            )
                            log.error(error)
                            raise Exception(error)
                        retry = True
                    else:
                        retry = False

            finally:
                if locked is True:
                    self.rwLock.release()

        return found
