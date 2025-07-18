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
"""contains utility functions for type checking"""

import logging
import re
import socket
from datetime import datetime, timedelta

import netaddr
from netaddr.ip import IPNetwork

from linotp.lib.crypto.encrypted_data import EncryptedData

DEFAULT_TIMEFORMAT = "%a, %d %b %Y %H:%M:%S GMT"

log = logging.getLogger(__name__)


class DurationParsingException(Exception):
    pass


duration_regex = re.compile(
    r"((?P<weeks>\d+?)(w|week|weeks))?"
    r"((?P<days>\d+?)(d|day|days))?"
    r"((?P<hours>\d+?)(h|hour|hours))?"
    r"((?P<minutes>\d+?)(m|minute|minutes))?"
    r"((?P<seconds>\d+?)(s|second|seconds))?$"
)


iso8601_duration_regex = re.compile(
    r"P((?P<years>\d+)Y)?"
    r"((?P<months>\d+)M)?"
    r"((?P<weeks>\d+)W)?"
    r"((?P<days>\d+)D)?"
    r"(T((?P<hours>\d+)H)?"
    r"((?P<minutes>\d+)M)?"
    r"((?P<seconds>\d+)S)?)?"
)


def parse_duration(duration_str, time_delta_compliant=False):
    """
    transform a duration string into a time delta object

    from:
        http://stackoverflow.com/questions/35626812/how-to-parse-timedelta-from-strings

    :param duration_str:  duration string like '1h' '3h 20m 10s' '10s'
                          or iso8601 durations like 'P23DT23H'
    :return: timedelta
    """

    # remove all white spaces for easier parsing
    duration_str = "".join(duration_str.split())

    if duration_str.upper().startswith("P"):
        parts = iso8601_duration_regex.match(duration_str.upper())
    else:
        parts = duration_regex.match(duration_str.lower())

    if not parts:
        msg = f"must be of type 'duration': {duration_str!r}"
        raise DurationParsingException(msg)

    parts = parts.groupdict()

    if time_delta_compliant and (
        "months" in parts or "weeks" in parts or "years" in parts
    ):
        # iso8601 defines month, weeks and years, while the python
        # timedelta does not support it for good reasons
        msg = f"definition {duration_str} is not python timedelta supported!"
        raise DurationParsingException(msg)

    time_params = {
        "days": 0,
        "hours": 0,
        "minutes": 0,
        "seconds": 0,
    }
    days_multiplier = {"years": 365, "months": 30, "weeks": 7}

    for name, param in parts.items():
        if param:
            if name in days_multiplier:
                time_params["days"] += days_multiplier[name] * float(param)
            else:
                time_params[name] += float(param)

    return timedelta(**time_params)


def is_duration(value):
    try:
        get_duration(value)

    except ValueError:
        return False

    return True


def get_duration(value):
    """
    return duration in seconds
    """
    try:
        return int(value)

    except ValueError:
        res = parse_duration(value)
        if res:
            return int(res.total_seconds())

    msg = f"not of type 'duration': {value}"
    raise ValueError(msg)


def is_integer(value):
    """
    type checking function for integers

    :param value: the to be checked value
    :return: return boolean
    """

    try:
        int(value)
    except ValueError:
        return False

    return True


def encrypted_data(value):
    """
    type converter for config entries -

    similar to int(bla) it will try to conveert the given value into
    an object of EncryptedData

    :return: EncyptedData object
    """

    # anything other than string will raise an error

    if not isinstance(value, str) and not isinstance(value, str):
        msg = "Unable to encode non textual data"
        raise Exception(msg)

    # if value is already encrypted we can just return

    if isinstance(value, EncryptedData):
        return value

    return EncryptedData.from_unencrypted(value)


def get_timeout(timeout, seperator=","):
    """
    get the timeout or timeout tuple from timeout input
    """
    if isinstance(timeout, tuple):
        return timeout

    if isinstance(timeout, float | int):
        return timeout

    if not isinstance(timeout, str):
        msg = "Unsupported timeout input type %r"
        raise ValueError(msg, timeout)

    try:
        if seperator not in timeout:
            return float(timeout)

    except ValueError as exx:
        msg = f"Failed to convert timeout {timeout!r} values!"
        raise ValueError(msg) from exx

    try:
        timeouts = tuple(
            float(x.strip()) for x in timeout.strip().strip(seperator).split(seperator)
        )

    except ValueError as exx:
        msg = f"Failed to convert timeout {timeout!r} values!"
        raise ValueError(msg) from exx

    if len(timeouts) == 1:
        return timeouts[0]

    if len(timeouts) == 2:
        return timeouts

    msg = "Unsupported timeout format %r"
    raise Exception(msg, timeout)


def boolean(value):
    """
    type converter for boolean config entries
    """
    true_def = (1, "1", "yes", "true", True)
    false_def = (0, "0", "no", "false", False)

    if isinstance(value, str):
        value = value.lower()

    if value not in true_def and value not in false_def:
        msg = f"unable to convert {value!r} to a boolean"
        raise ValueError(msg)

    return value in true_def


def check_time_format_string(time_format_string):
    """
    check if a given parameter is a valid time filter format

    :param timefilter_format: the term which should describe datetime format
                    eg. "%d, %m, %H, %I, %M, %S, %J"
    :return: boolean - true if this is valid format string
    """
    # due to historical reasons we have to support as well booleans

    if time_format_string in [True, False]:
        return True
    if time_format_string.lower() in ("true", "false"):
        return True

    # verify that the given format could be applied

    try:
        now = datetime.utcnow()
        dt_str = now.strftime(time_format_string)
        _now_stripped = datetime.strptime(dt_str, time_format_string)
        return True
    except ValueError as exx:
        log.error("invalid time filter format: %r: %r", time_format_string, exx)
        return False


def check_networks_expression(networks):
    """
    check if a given term is realy a description of networks

    :param networks: the term which should describe a network
                    eg. "192.168.178.1/24, example.com/32"
    :return: boolean - true if this is a network description
    """

    if not isinstance(networks, str) and not isinstance(networks, str):
        return False

    networks = networks.strip()

    # we require to accept, otherwise the setConfig will fail
    if networks == "":
        return True

    return all(is_network(network) for network in networks.split(","))


def is_network(network):
    """
    test if a given term is realy a network description

    :param network: the term which should describe a network
                    eg. 192.168.178.1/24 or example.com/32
    :return: boolean - true if this is a network description
    """
    return get_ip_network(network) is not None


def get_ip_network(network):
    """
    get the ip network representation from netaddr

    :param network: the term which should describe a network
                    eg. 192.168.178.1/24 or example.com/32
    :return: None or the netaddr.IPNetwork object
    """

    if not network or not network.strip():
        return None

    network = network.strip()

    try:
        ip_network = netaddr.IPNetwork(network)
        return ip_network

    except netaddr.core.AddrFormatError:
        try:
            # support for cidr on named network like 'linotp.de/29'
            cidr = None
            if "/" in network:
                network, _sep, cidr = network.rpartition("/")

            ip_addr = socket.gethostbyname(network)

            if cidr:
                ip_addr = ip_addr + "/" + cidr

            ip_network = netaddr.IPNetwork(ip_addr)
            return ip_network

        except socket.gaierror:
            return None

    return None


def get_ip_address(address):
    """
    get the ip address representation from netaddr

    :param address: the term which should describe a ip address
                    eg. 192.168.178.1 or www.example.com
    :return: None or the netaddr.IPAddress object
    """
    if not address or not address.strip():
        return None

    address = address.strip()

    try:
        ip_address = netaddr.IPAddress(address)
        return ip_address

    except (netaddr.core.AddrFormatError, ValueError):
        try:
            ip_addr_str = socket.gethostbyname(address)
            ip_address = netaddr.IPNetwork(ip_addr_str)

            if isinstance(ip_address, IPNetwork):
                return ip_address.ip

            return ip_address

        except socket.gaierror:
            return None

    return None


def is_ip_address(address):
    """
    get the ip address representation from netaddr

    :param address: the term which should describe a ip address
                    eg. 192.168.178.1 or www.example.com
    :return: boolean - true if it is an IPAddress
    """
    return get_ip_address(address) is not None


_dotted_quad_regex = re.compile(r"^\d+(\.\d+){3}$")


def is_ip_address_dotted_quad(address):
    """Check whether `address` is an IP address in dotted-quad notation.
    `is_ip_address()` will also accept DNS names, which is not what we want.
    `netaddr.IPAddress()` returns valid results for strange input like `1.2`,
    which might technically be an IP address but is not what people expect,
    so we don't bother with it.
    Note that this will fail dismally in an IPv6 environment.
    """
    return bool(  # Use `bool` here to turn `None` into `False`
        _dotted_quad_regex.match(address)
    ) and all(0 <= int(q) < 256 for q in address.split("."))


def parse_timeout(timeout_val, seperator=","):
    """
    parse a timeout value which migth be a single value or a tuple of
    connection and response timeouts

    :params timeout_val: timeout value which could be either string, tuple
                         or float/int

    :return: timeout tuple of float or float/int timeout value
    """

    if isinstance(timeout_val, tuple):
        return timeout_val

    if isinstance(timeout_val, str):
        if seperator in timeout_val:
            connection_time, response_time = timeout_val.split(seperator)
            return (float(connection_time), float(response_time))
        else:
            return float(timeout_val)

    if isinstance(timeout_val, float | int):
        return timeout_val

    msg = "unsupported timeout format"
    raise ValueError(msg)


def convert_to_datetime(date_str, time_formats):
    """Convert a string to a datetime object by one of the time format strings.

    :param date_str: date string
    :param time_formats: list of time formats, which the date string should match
    """
    if not isinstance(date_str, str):
        msg = "given parameter is not a string"
        raise Exception(msg)

    err = []
    for time_format_string in time_formats:
        try:
            date_obj = datetime.strptime(date_str, time_format_string)
            return date_obj
        except ValueError as exx:
            err.append(f"{exx!r}")

    msg = f"Failed to convert start time paramter to timestamp {err!r}"
    raise Exception(msg)
