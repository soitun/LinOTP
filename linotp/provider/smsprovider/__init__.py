#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010-2019 KeyIdentity GmbH
#    Copyright (C) 2019-     netgo software GmbH
#
#    This file is part of LinOTP smsprovider.
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
LinOTP is an open solution for strong two-factor authentication
       with One Time Passwords.

SMSProvider is the interface to the final sms submitting service
LinOTP provides 3 types of implementation: HTTPSMS, SMTP and Device
sms submit.

"""


# IMPORTANT! This file is imported by setup.py, therefore do not (directly or
# indirectly) import any module that might not yet be installed when installing
# SMSProvider.

__copyright__ = "Copyright (C) netgo software GmbH"
__license__ = "Gnu AGPLv3"
__contact__ = "www.linotp.org"
__email__ = "info@linotp.de"
__version__ = "2.12"


class ISMSProvider:
    """
    Interface class for the SMS providers
    """

    provider_type = "sms"

    # SMS Provider Timeout
    # To prevent that LinOTP will be blocked due to an unlimited timeout
    # we set here a default timeout of 5 seconds.
    # The default timeout is only the connection timeout. To specify the
    # data transmission timeout e.g. of 10 seconds a tuple of (5, 10) could be
    # defined with most of the SMS provider definitions
    DEFAULT_TIMEOUT = 5

    def __init__(self):
        self.config = {}

    @staticmethod
    def getConfigMapping():
        """
        for dynamic, adaptive config entries we provide the abilty to
        have dedicated config entries

        entries should look like:
        {
          key: (ConfigName, ConfigType)
        }
        """
        config_mapping = {
            "timeout": ("Timeout", None),
            "config": ("Config", "encrypted_data"),
        }

        return config_mapping

    @classmethod
    def getClassInfo(cls, key=None):
        return {}

    def _submitMessage(self, phone, message):
        msg = "Every subclass of ISMSProvider has to implement this method."
        raise NotImplementedError(msg)

    def submitMessage(self, phone, message):
        """
        submitMessage - the method of all SMS Providers after preparation
                        the subclass method of _submitMessage() is called

        :param phone: the unformatted, arbitrary phone number
        :param message: the message that should be submitted
        :return: boolean value of success
        """

        # should we transform the phone number according to the MSISDN standard
        msisdn = ISMSProvider.get_bool(self.config, "MSISDN", False)
        if msisdn:
            phone = self._get_msisdn_phonenumber(phone)

        # suppress_prefix is about to cut off the leading prefix e.g. '+' sign
        # leading with the meaning, that there are only leading white spaces
        suppress_prefix = self.config.get("SUPPRESS_PREFIX", "")
        if suppress_prefix:
            phone = phone.lstrip()
            if phone[0 : len(suppress_prefix)] == suppress_prefix:
                phone = phone[len(suppress_prefix) :]

        return self._submitMessage(phone, message)

    def loadConfig(self, configDict):
        self.config = configDict

    @staticmethod
    def _get_msisdn_phonenumber(phonenumber):
        """
        convert the phone number to something more msisdn compliant

        from http://www.msisdn.org/:
          In GSM standard 1800, this number is built up as
            MSISDN = CC + NDC + SN
            CC = Country Code
            NDC = National Destination Code
            SN = Subscriber Number

        there are two version of the msisdn: the global definition and
        the local definition, with the difference, that the global definition
        might start with an +CC country code. in this conversion routine, the
        global prefixing is ignored
        """
        with_prefix = phonenumber.strip().startswith("+")
        phone = "".join(char for char in phonenumber if char.isdigit())
        return "+" + phone if with_prefix else phone

    @staticmethod
    def get_bool(config, key, default):
        """
        helper method - get the boolean value from a config entry,
                        which could be either boolean or string

        as we might get from the json a real boolean or a string, we use
        the %r to print the representation to generalize the processing
        """
        as_str = str(config.get(key, default))
        return as_str.lower() == "true"


def getSMSProviderClass(packageName, className):
    """
    helper method to load the SMSProvider class from a given
    package in literal: checks, if the submittMessage method exists
    else an error is thrown

    example:
        getSMSProviderClass("SkypeSMSProvider", "SMSProvider")()

    :return: the SMS provider object

    """

    mod = __import__(packageName, globals(), locals(), [className], 1)
    klass = getattr(mod, className)
    if not hasattr(klass, "submitMessage"):
        msg = (
            f"SMSProvider AttributeError: {packageName!r}.{className!r} "
            "instance of SMSProvider has no method 'submitMessage'"
        )
        raise NameError(msg)
    else:
        return klass


# eof #
