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
error controller - to display errors
"""

from html import escape

from flask import request
from webhelpers2.html.builder import literal

from linotp.controllers.base import BaseController
from linotp.flap import error_document_template
from linotp.lib import deprecated_methods
from linotp.lib.util import str2unicode


class ErrorController(BaseController):
    jwt_exempt = True  # Don't do JWT auth in this controller

    @deprecated_methods(["POST"])
    def document(self):
        """Render the error document"""

        # TODO: this will break - adjust to flask response

        resp = request.environ.get("pylons.original_response")
        if resp is not None:
            unicode_body = str2unicode(resp.body)
            content = literal(unicode_body)
        else:
            message = request.GET.get("message", request.POST.get("message", ""))
            content = escape(message)

        code = request.GET.get("code", request.POST.get("code", str(resp.status_int)))

        page = error_document_template % {
            "prefix": request.environ.get("SCRIPT_NAME", ""),
            "code": escape(code),
            "message": content,
        }
        return page

    @deprecated_methods(["POST"])
    def img(self, id):
        """Serve Pylons' stock images"""
        return self._serve_file("/".join(["media/img", id]))

    @deprecated_methods(["POST"])
    def style(self, id):
        """Serve Pylons' stock stylesheets"""
        return self._serve_file("/".join(["media/style", id]))

    def _serve_file(self, path):
        """Call Paste's FileApp (a WSGI application) to serve the file
        at the specified path
        """
        request.environ["PATH_INFO"] = f"/{path}"
        return (
            "<html><body>"
            "<p>Failed to forward to WSGI application (Pylons "
            "incompatibility).</p>"
            "</body></html>"
        )


# eof###########################################################################
