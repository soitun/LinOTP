# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2016 KeyIdentity GmbH
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
#    E-mail: linotp@lsexperts.de
#    Contact: www.linotp.org
#    Support: www.lsexperts.de
#
'''The Controller's Base class '''
import os
import re

from pylons.i18n.translation import _ as translate
from pylons.i18n.translation import set_lang
from pylons.i18n import LanguageError

from pylons.controllers import WSGIController

from pylons import tmpl_context as c
from pylons import config
from pylons import request

from linotp.lib.config import initLinotpConfig
from linotp.lib.resolver import initResolvers
from linotp.lib.resolver import setupResolvers
from linotp.lib.resolver import closeResolvers
from linotp.lib.user import getUserFromRequest
from linotp.lib.user import getUserFromParam
from linotp.lib.realm import getDefaultRealm
from linotp.lib.realm import getRealms

from linotp.lib.config import getGlobalObject
from linotp.lib.crypt import init_key_partition


from linotp.model import meta
from linotp.lib.openid import SQLStorage

from linotp.lib.context import request_context
from linotp.lib.context import request_context_safety

# this is a hack for the static code analyser, which
# would otherwise show session.close() as error
import linotp.model.meta

from linotp.lib.config import getLinotpConfig
from linotp.lib.policy import getPolicies
from linotp.lib.util import get_client

import logging
log = logging.getLogger(__name__)

Session = linotp.model.meta.Session

Audit = config.get('audit')

# HTTP-ACCEPT-LANGUAGE strings are in the form of i.e.
# de-DE, de; q=0.7, en; q=0.3
accept_language_regexp = re.compile(r'\s*([^\s;,]+)\s*[;\s*q=[0-9.]*]?\s*,?')


def set_config(key, value, typ, description=None):
    '''
    create an intial config entry, if it does not exist

    :param key: the key
    :param value: the value
    :param description: the description of the key

    :return: nothing
    '''

    count = Session.query(linotp.model.Config).filter(
                          linotp.model.Config.Key == "linotp." + key).count()

    if count == 0:
        config_entry = linotp.model.Config(key, value,
                                           Type=typ, Description=description)
        Session.add(config_entry)

    return


def set_defaults():
    '''
    add linotp default config settings

    :return: - nothing -
    '''

    is_upgrade = 0 != Session.query(linotp.model.Config).filter().count()

    if(is_upgrade):
        # if it is an upgrade and no welcome screen was shown before,
        # make sure an upgrade screen is shown
        set_config(key="welcome_screen.version",
                   value="0", typ="text")

    log.info("Adding config default data...")

    set_config(key="DefaultMaxFailCount",
               value="10", typ="int",
               description=("The default maximum count for"
                            " unsuccessful logins"))

    set_config(key="DefaultCountWindow",
               value="10", typ="int",
               description=("The default lookup window for tokens "
                            "out of sync "))

    set_config(key="DefaultSyncWindow",
               value="1000", typ="int",
               description=("The default lookup window for tokens "
                            "out of sync "))

    set_config(key="DefaultChallengeValidityTime",
               value="120", typ="int",
               description=("The default time, a challenge is regarded"
                            " as valid."))

    set_config(key="DefaultResetFailCount",
               value="True", typ="bool",
               description="The default maximum count for unsucessful logins")

    set_config(key="DefaultOtpLen",
               value="6", typ="int",
               description="The default len of the otp values")

    set_config(key="QRTokenOtpLen",
               value="8", typ="int",
               description="The default len of the otp values")

    set_config(key="QRChallengeValidityTime",
               value="150", typ="int",
               description=("The default qrtoken time, a challenge is regarded"
                            " as valid."))

    set_config(key="QRMaxChallenges",
               value="4", typ="int",
               description="Maximum open QRToken challenges")

    set_config(key="PushChallengeValidityTime",
               value="150", typ="int",
               description=("The pushtoken default time, a challenge is "
                            "regarded as valid."))

    set_config(key="PushMaxChallenges",
               value="4", typ="int",
               description="Maximum open pushtoken challenges")

    set_config(key="PrependPin",
               value="True", typ="bool",
               description="is the pin prepended - most cases")

    set_config(key="FailCounterIncOnFalsePin",
               value="True", typ="bool",
               description="increment the FailCounter, if pin did not match")

    set_config(key="SMSProvider",
               value="smsprovider.HttpSMSProvider.HttpSMSProvider",
               typ="text",
               description="SMS Default Provider via HTTP")

    set_config(key="SMSProviderTimeout",
               value="300", typ="int",
               description="Timeout until registration must be done")

    set_config(key="SMSBlockingTimeout",
               value="30", typ="int",
               description="Delay until next challenge is created")

    set_config(key="DefaultBlockingTimeout",
               value="0", typ="int",
               description="Delay until next challenge is created")

    # setup for totp defaults
    # "linotp.totp.timeStep";"60";"None";"None"
    # "linotp.totp.timeWindow";"600";"None";"None"
    # "linotp.totp.timeShift";"240";"None";"None"

    set_config(key="totp.timeStep",
               value="30", typ="int",
               description="Time stepping of the time based otp token ")

    set_config(key="totp.timeWindow",
               value="300", typ="int",
               description=("Lookahead time window of the time based "
                            "otp token "))

    set_config(key="totp.timeShift",
               value="0", typ="int",
               description="Shift between server and totp token")

    set_config(key="AutoResyncTimeout",
               value="240", typ="int",
               description="Autosync timeout for an totp token")

    # setup for ocra defaults
    # OcraDefaultSuite
    # QrOcraDefaultSuite
    # OcraMaxChallenges
    # OcraChallengeTimeout

    set_config(key="OcraDefaultSuite",
               value="OCRA-1:HOTP-SHA256-8:C-QN08",
               typ="string",
               description="Default OCRA suite for an ocra token ")

    set_config(key="QrOcraDefaultSuite",
               value="OCRA-1:HOTP-SHA256-8:C-QA64",
               typ="string",
               description="Default OCRA suite for an ocra token ")

    set_config(key="OcraMaxChallenges",
               value="4", typ="int",
               description="Maximum open ocra challenges")

    set_config(key="OcraChallengeTimeout",
               value="300", typ="int",
               description="Timeout for an open ocra challenge")

    # emailtoken defaults
    set_config(key="EmailProvider",
               value="linotp.provider.emailprovider.SMTPEmailProvider",
               typ="string",
               description="Default EmailProvider class")

    set_config(key="EmailChallengeValidityTime",
               value="600", typ="int",
               description=("Time that an e-mail token challenge stays valid"
                            " (seconds)"))
    set_config(key="EmailBlockingTimeout",
               value="120", typ="int",
               description="Time during which no new e-mail is sent out")

    set_config(key='OATHTokenSupport',
               value="False", typ="bool",
               description="support for hmac token in oath format")

    # use the system certificate handling, especially for ldaps
    set_config(key="certificates.use_system_certificates",
               value="False", typ="bool",
               description="use system certificate handling")

    set_config(key="user_lookup_cache.enabled",
               value="False", typ="bool",
               description="enable user loookup caching")

    set_config(key="resolver_lookup_cache.enabled",
               value="False", typ="bool",
               description="enable realm resolver caching")

    set_config(key='user_lookup_cache.expiration',
               value="64800", typ="int",
               description="expiration of user caching entries")

    set_config(key='resolver_lookup_cache.expiration',
               value="64800", typ="int",
               description="expiration of resolver caching entries")

    return


def setup_app(conf, conf_global=None, unitTest=False):
    '''
    setup_app is the hook, which is called, when the application is created

    :param conf: the application configuration

    :return: - nothing -
    '''
    if conf_global is not None:
        if conf_global.has_key("sqlalchemy.url"):
            log.info("sqlalchemy.url")
    else:
        conf.get("sqlalchemy.url", None)

    if unitTest is True:
        log.info("Deleting previous tables...")
        meta.metadata.drop_all(bind=meta.engine)

    # Create the tables if they don't already exist
    log.info("Creating tables...")
    meta.metadata.create_all(bind=meta.engine)

    if conf.has_key("linotpSecretFile"):
        filename = conf.get("linotpSecretFile")
        try:
            with open(filename):
                pass
        except IOError:
            log.warning("The Linotp Secret File could not be found " +
                        "-creating a new one: %s" % filename)
            f_handle = open(filename, 'ab+')
            secret = os.urandom(32 * 5)
            f_handle.write(secret)
            f_handle.close()
            os.chmod(filename, 0400)
        log.info("linotpSecretFile: %s" % filename)

    set_defaults()

    Session.commit()

    log.info("Successfully set up.")


class BaseController(WSGIController):
    """
    BaseController class - will be called with every request
    """

    def __init__(self, *args, **kw):
        """
        base controller constructor

        :param *args: generic argument array
        :param **kw: generic argument dict
        :return: None

        """
        self.sep = None
        self.set_language(request.headers)
        self.base_auth_user = ''

        self.parent = super(WSGIController, self)
        self.parent.__init__(*args, **kw)

        # make the OpenID SQL Instance globally available
        openid_sql = config.get('openid_sql', None)
        if openid_sql is None:
            try:
                openid_storage = SQLStorage()
                config['openid_sql'] = openid_storage
            except Exception as exx:
                config['openid_sql'] = exx
                log.error("Failed to configure openid_sql: %r" % exx)

        first_run = False
        app_setup_done = config.get('app_setup_done', False)
        if app_setup_done is False:
            try:
                setup_app(config)
                config['app_setup_done'] = True
                first_run = True
            except Exception as exx:
                config['app_setup_done'] = False
                log.error("Failed to serve request: %r" % exx)
                raise exx

        # set the decryption device before loading linotp config,
        # so it contains the decrypted values as well
        glo = getGlobalObject()
        self.sep = glo.security_provider

        try:
            hsm = self.sep.getSecurityModule()
            self.hsm = hsm
            c.hsm = hsm
        except Exception as exx:
            log.exception('failed to assign hsm device: %r' % exx)
            raise exx

        l_config = initLinotpConfig()

        # initialize the elliptic curve secret + public key for the qrtoken
        secret_key = l_config.get('SecretKey.Partition.0', False)

        if not secret_key:
            init_key_partition(l_config, partition=0)

        resolver_setup_done = config.get('resolver_setup_done', False)
        if resolver_setup_done is False:
            try:
                cache_dir = config.get("app_conf", {}).get("cache_dir", None)
                setupResolvers(config=l_config, cache_dir=cache_dir)
                config['resolver_setup_done'] = True
            except Exception as exx:
                config['resolver_setup_done'] = False
                log.error("Failed to setup resolver: %r" % exx)
                raise exx

        # TODO: verify merge dropped
        # initResolvers()

        # if we are in the setup cycle, we check for the linotpLicenseFile
        if first_run:
            if "linotpLicenseFile" in config and 'license' not in l_config:
                license_str = ''
                filename = config.get("linotpLicenseFile", '')
                try:
                    with open(filename) as f:
                        license_str = f.read()
                except IOError:
                    log.error("linotpLicenseFile: %s" % filename)

                if not license_str:
                    log.error("empty license file: %s" % filename)
                else:
                    with request_context_safety():
                        request_context['translate'] = translate

                        import linotp.lib.support
                        res, msg = linotp.lib.support.setSupportLicense(license_str)
                        if res is False:
                            log.error("failed to load license: %s: %s"
                                      % (license_str, msg))

                        else:
                            log.info("license successfully loaded")

        return

    def __call__(self, environ, start_response):
        '''Invoke the Controller'''
        # WSGIController.__call__ dispatches to the Controller method
        # the request is routed to. This routing information is
        # available in environ['pylons.routes_dict']

        path = ""

        with request_context_safety():

            self.create_context(request, environ)

            try:
                if environ:
                    path = environ.get("PATH_INFO", "") or ""

                try:
                    user_desc = getUserFromRequest(request)
                    self.base_auth_user = user_desc.get('login', '')
                except UnicodeDecodeError as exx:
                    # we supress Exception here as it will be handled in the
                    # controller which will return corresponding response
                    log.info('Failed to identify user due to %r' % exx)

                log.debug("request %r" % path)
                ret = WSGIController.__call__(self, environ, start_response)
                log.debug("reply %r" % ret)

            finally:
                meta.Session.remove()
                # free the lock on the scurityPovider if any
                if self.sep:
                    self.sep.dropSecurityModule()
                closeResolvers()

                # hint for the garbage collector to make the dishes
                data_objects = ["resolvers_loaded", "resolver_types",
                                "resolver_clazzes", "linotpConfig", "audit", "hsm"]
                for data_obj in data_objects:
                    if hasattr(c, data_obj):
                        data = getattr(c, data_obj)
                        del data

                log.debug("request %r done!" % path)

            return ret

    def set_language(self, headers):
        '''Invoke before everything else. And set the translation language'''
        languages = headers.get('Accept-Language', '')

        found_lang = False

        for match in accept_language_regexp.finditer(languages):
            # make sure we have a correct language code format
            language = match.group(1)
            if not language:
                continue
            language = language.replace('_', '-').lower()

            # en is the default language
            if language.split('-')[0] == 'en':
                found_lang = True
                break

            try:
                set_lang(language.split('-')[0])
                found_lang = True
                break
            except LanguageError:
                log.debug("Cannot set requested language: %s. Trying next"
                          " language if available.", language)

        if not found_lang and languages:
            log.warning("Cannot set preferred language: %r", languages)

        return

    def create_context(self, request, environment):
        """
        create the request context for all controllers
        """

        linotp_config = getLinotpConfig()

        request_context['Config'] = linotp_config
        request_context['Policies'] = getPolicies()
        request_context['translate'] = translate
        request_context['CacheManager'] = environment['beaker.cache']

        initResolvers()

        request_params = {}

        try:
            request_params.update(request.params)
        except UnicodeDecodeError as exx:
            log.error("Faild to decode request parameters %r" % exx)

        request_context['Params'] = request_params

        authUser = None
        try:
            authUser = getUserFromRequest(request)
        except UnicodeDecodeError as exx:
            log.error("Faild to decode request parameters %r" % exx)

        request_context['AuthUser'] = authUser

        requestUser = None
        try:
            requestUser = getUserFromParam(request_params, True)
        except UnicodeDecodeError as exx:
            log.error("Faild to decode request parameters %r" % exx)
        request_context['RequestUser'] = requestUser

        client = None
        try:
            client = get_client(request=request)
        except UnicodeDecodeError as exx:
            log.error("Faild to decode request parameters %r" % exx)

        request_context['Client'] = client

        request_context['Audit'] = Audit
        request_context['audit'] = Audit.initialize(request, client=client)

        defaultRealm = ""
        try:
            defaultRealm = getDefaultRealm(linotp_config)
        except UnicodeDecodeError as exx:
            log.error("Faild to decode request parameters %r" % exx)

        request_context['defaultRealm'] = defaultRealm

        realms = None
        try:
            realms = getRealms()
        except UnicodeDecodeError as exx:
            log.error("Faild to decode request parameters %r" % exx)

        request_context['Realms'] = realms

        request_context['hsm'] = None
        if hasattr(self, "hsm"):
            request_context['hsm'] = self.hsm

        # copy some system entries from pylons
        syskeys = {
                   "radius.nas_identifier": "LinOTP",
                   "radius.dictfile": "/etc/linotp2/dictionary"
        }

        sysconfig = {}
        for key, default in syskeys.items():
            try:
                sysconfig[key] = config.get(key, default)
            except:
                log.info('no sytem config entry %s' % key)

        request_context['SystemConfig'] = sysconfig

# eof ########################################################################
