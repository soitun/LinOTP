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
"""contains utility functions to load dynamic modules"""

import importlib
import logging
import pkgutil
import sys

log = logging.getLogger(__name__)


def import_submodules(package_name):
    """Import all submodules of a module, recursively

    :param package_name: Package name
    :type package_name: str
    :rtype: dict[types.ModuleType]
    """

    package = sys.modules[package_name]

    p_list = {}

    for _loader, name, _is_pkg in pkgutil.walk_packages(package.__path__):
        try:
            p_list[name] = importlib.import_module(package_name + "." + name)

        except Exception as exx:
            log.error("Failed to load %r - %r", name, exx)

    return p_list


# eof #
