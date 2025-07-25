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
This is the Audit Class, that writes Audits to SQL DB

uses a public/private key for signing the log entries

    # create keypair:
    # openssl genrsa -out private.pem 2048
    # extract the public key:
    # openssl rsa -in private.pem -pubout -out public.pem

"""

import datetime
import logging
from binascii import unhexlify

from flask import current_app
from sqlalchemy import Column, and_, asc, desc, or_, schema, types
from sqlalchemy.orm import validates

from linotp.lib.audit.base import AuditBase
from linotp.lib.crypto.rsa import RSA_Signature
from linotp.model import db, implicit_returning

log = logging.getLogger(__name__)


def now() -> str:
    """
    Returns an ISO datetime representation in UTC timezone with millisecond
    precision to fit in the AuditTable.timestamp column
    """
    return datetime.datetime.now(datetime.UTC).isoformat(timespec="milliseconds")


######################## MODEL ################################################


class AuditTable(db.Model):
    # query against the "auditdb" database session
    __bind_key__ = "auditdb"

    __table_args__ = {
        "implicit_returning": implicit_returning,
    }

    __tablename__ = "audit"
    id = Column(
        types.Integer,
        schema.Sequence("audit_seq_id", optional=True),
        primary_key=True,
    )
    timestamp = Column(types.Unicode(30), default=now, index=True)
    signature = Column(types.Unicode(512), default="")
    action = Column(types.Unicode(30), index=True)
    success = Column(types.Unicode(30), default="0")
    serial = Column(types.Unicode(30), index=True)
    tokentype = Column(types.Unicode(40))
    user = Column(types.Unicode(255), index=True)
    realm = Column(types.Unicode(255), index=True)
    administrator = Column(types.Unicode(255))
    action_detail = Column(types.Unicode(512), default="")
    info = Column(types.Unicode(512), default="")
    linotp_server = Column(types.Unicode(80))
    client = Column(types.Unicode(80))
    log_level = Column(types.Unicode(20), default="INFO", index=True)
    clearance_level = Column(types.Integer, default=0)

    @validates(
        "serial",
        "action",
        "success",
        "tokentype",
        "user",
        "realm",
        "administrator",
        "linotp_server",
        "client",
        "log_level",
    )
    def convert_str(self, key, value):
        """
        Converts the validated column to string on insert
        and truncates the values if necessary
        """
        error_on_truncate = current_app.config["AUDIT_ERROR_ON_TRUNCATION"]
        return self.validate_truncate(
            key,
            str(value or ""),
            warn=True,
            error=error_on_truncate,
        )

    @validates("action_detail", "info")
    def validate_truncate(self, key, value, warn=False, error=False):
        """
        Silently truncates the validated column if value is exceeding column
        length.
        If called manually, can be used to log a warning or throw an exception
        on truncation.
        """
        max_len = getattr(self.__class__, key).prop.columns[0].type.length
        if value and len(value) > max_len:
            if warn:
                log.warning("truncating audit data: [audit.%s] %s", key, value)
            if error:
                msg = (
                    f"Audit data too long, not truncating [audit.{key}] {value}"
                    " because AUDIT_ERROR_ON_TRUNCATION is active."
                )
                raise ValueError(msg)

            value = value[: max_len - 1] + "…"
        return value


###############################################################################
class Audit(AuditBase):
    """
    Audit Implementation to the generic audit interface

    This class provides audit capabilities mapped to an SQLAlchemy
    backend which has a separate database connection.
    """

    def __init__(self):
        """
        Initialise the audit backend

        Here the audit backend is initialised.

        The SQLAlchemy connection is configured via flask_sqlalchemy in
        :func:`~linotp.model.setup_db`.
        """

        super().__init__()

        # initialize signing keys
        self.readKeys()

        try:
            private_key = self.private.encode("utf-8")
            self.rsa = RSA_Signature(private=private_key)
        except Exception as exx:
            log.error(
                "Failed to run the RSA_Signature intitalisation %r: %r",
                private_key,
                exx,
            )
            raise exx

    def _attr_to_dict(self, audit_line):
        line = {}
        line["number"] = audit_line.id
        line["id"] = audit_line.id
        line["date"] = str(audit_line.timestamp)
        line["timestamp"] = str(audit_line.timestamp)
        line["missing_line"] = ""
        line["serial"] = audit_line.serial
        line["action"] = audit_line.action
        line["action_detail"] = audit_line.action_detail
        line["success"] = audit_line.success
        line["token_type"] = audit_line.tokentype
        line["tokentype"] = audit_line.tokentype
        line["user"] = audit_line.user
        line["realm"] = audit_line.realm
        line["administrator"] = f"{audit_line.administrator!r}"
        line["action_detail"] = audit_line.action_detail
        line["info"] = audit_line.info
        line["linotp_server"] = audit_line.linotp_server
        line["client"] = audit_line.client
        line["log_level"] = audit_line.log_level
        line["clearance_level"] = audit_line.clearance_level

        return line

    def _sign(self, audit_line):
        """
        Create a signature of the audit object
        """
        line = self._attr_to_dict(audit_line)
        s_audit = getAsBytes(line)

        signature = self.rsa.sign(s_audit)
        return signature.hex()

    def _verify(self, auditline, signature):
        """
        Verify the signature of the audit line
        """
        res = False
        if not signature:
            log.debug("[_verify] missing signature %r", auditline)
            return res

        s_audit = getAsBytes(auditline)

        return self.rsa.verify(s_audit, unhexlify(signature))

    def log(self, param):
        """
        This method is used to log the data. It splits information of
        multiple tokens (e.g from import) in multiple audit log entries
        """

        try:
            serial = param.get("serial", "") or ""
            if not serial:
                # if no serial, do as before
                self.log_entry(param)
            else:
                # look if we have multiple serials inside
                serials = serial.split(",")
                for serial in serials:
                    p = {**param, "serial": serial}
                    self.log_entry(p)

        except Exception as exx:
            log.error("[log] error writing log message: %r", exx)
            db.session.rollback()
            raise exx

    def log_entry(self, param):
        """
        This method is used to log the data.
        It should hash the data and do a hash chain and sign the data
        """

        at = AuditTable(
            serial=param.get("serial"),
            action=param.get("action").lstrip("/"),
            success="1" if param.get("success") else "0",
            tokentype=param.get("token_type"),
            user=param.get("user"),
            realm=param.get("realm"),
            administrator=param.get("administrator"),
            action_detail=param.get("action_detail"),
            info=param.get("info"),
            linotp_server=param.get("linotp_server"),
            client=param.get("client"),
            log_level=param.get("log_level"),
            clearance_level=param.get("clearance_level"),
        )

        db.session.add(at)
        db.session.flush()
        # At this point "at" contains the primary key id and we can sign the audit entry
        at.signature = self._sign(at)
        db.session.commit()

    def initialize_log(self, param):
        """
        This method initialized the log state.
        The fact, that the log state was initialized, also needs to be logged.
        Therefor the same params are passed as i the log method.
        """

    def set(self):
        """
        This function could be used to set certain things like the signing key.
        But maybe it should only be read from linotp.cfg?
        """

    def _buildCondition(self, param, AND):
        """
        create the sqlalchemy condition from the params
        """
        key_mapping = {
            "serial": AuditTable.serial,
            "user": AuditTable.user,
            "realm": AuditTable.realm,
            "action": AuditTable.action,
            "action_detail": AuditTable.action_detail,
            "date": AuditTable.timestamp,
            "number": AuditTable.id,
            "success": AuditTable.success,
            "tokentype": AuditTable.tokentype,
            "administrator": AuditTable.administrator,
            "info": AuditTable.info,
            "linotp_server": AuditTable.linotp_server,
            "client": AuditTable.client,
            "log_level": AuditTable.log_level,
            "clearance_level": AuditTable.clearance_level,
        }

        conditions = [
            key_mapping[k].like(v)
            for k, v in param.items()
            if v != "" and k in key_mapping
        ]

        boolCheck = and_ if AND else or_
        all_conditions = boolCheck(*conditions) if conditions else None

        return all_conditions

    def row2dict(self, audit_line):
        """
        convert an SQL audit db to a audit dict

        :param audit_line: audit db row
        :return: audit entry dict
        """

        line = self._attr_to_dict(audit_line)

        # replace None values with an empty string
        line = {key: value if value is not None else "" for key, value in line.items()}

        # Signature check
        # TODO: use instead the verify_init
        sig_check_result = self._verify(line, audit_line.signature)
        line["sig_check"] = "OK" if sig_check_result == 1 else "FAIL"

        return line

    def row2dictApiV2(self, audit_line):
        """
        convert an SQL audit db to a audit dict for /api/v2/auditlog

        :param audit_line: audit db row
        :return: audit entry dict
        """

        line = self._attr_to_dict(audit_line)

        audit_dict = {
            "id": line["id"],
            "timestamp": line.get("timestamp"),
            "serial": line.get("serial"),
            "action": line.get("action"),
            "actionDetail": line.get("action_detail"),
            "success": line.get("success", "0") == "1",
            "tokenType": line.get("tokentype"),
            "user": line.get("user"),
            "realm": line.get("realm"),
            "administrator": line.get("administrator"),
            "info": line.get("info"),
            "linotpServer": line.get("linotp_server"),
            "client": line.get("client"),
            "logLevel": line.get("log_level"),
            "clearanceLevel": line.get("clearance_level"),
            "signatureCheck": self._verify(line, audit_line.signature),
        }

        # Map empty string to None
        audit_dict = {
            k: v if v not in {"", "''"} else None for k, v in audit_dict.items()
        }

        return audit_dict

    def searchQuery(self, param, AND=True, display_error=True, rp_dict=None):
        """
        This function is used to search audit events.

        param:
            Search parameters can be passed.

        return:
            a result object which has to be converted with iter() to an
            iterator
        """

        if rp_dict is None:
            rp_dict = {}

        if "or" in param and param["or"].lower() == "true":
            AND = False

        # build the condition / WHERE clause
        condition = self._buildCondition(param, AND)

        order = AuditTable.id
        if rp_dict.get("sortname"):
            sortn = rp_dict.get("sortname").lower()
            if sortn == "serial":
                order = AuditTable.serial
            elif sortn == "number":
                order = AuditTable.id
            elif sortn == "user":
                order = AuditTable.user
            elif sortn == "action":
                order = AuditTable.action
            elif sortn == "action_detail":
                order = AuditTable.action_detail
            elif sortn == "realm":
                order = AuditTable.realm
            elif sortn == "date":
                order = AuditTable.timestamp
            elif sortn == "administrator":
                order = AuditTable.administrator
            elif sortn == "success":
                order = AuditTable.success
            elif sortn == "tokentype":
                order = AuditTable.tokentype
            elif sortn == "info":
                order = AuditTable.info
            elif sortn == "linotp_server":
                order = AuditTable.linotp_server
            elif sortn == "client":
                order = AuditTable.client
            elif sortn == "log_level":
                order = AuditTable.log_level
            elif sortn == "clearance_level":
                order = AuditTable.clearance_level

        # build the ordering
        order_dir = asc(order)

        if rp_dict.get("sortorder"):
            sorto = rp_dict.get("sortorder").lower()
            if sorto == "desc":
                order_dir = desc(order)

        if condition is None:
            audit_q = db.session.query(AuditTable).order_by(order_dir)
        else:
            audit_q = db.session.query(AuditTable).filter(condition).order_by(order_dir)

        # FIXME? BUT THIS IS SO MUCH SLOWER!
        # FIXME: Here desc() ordering also does not work! :/

        if "rp" in rp_dict or "page" in rp_dict:
            # build the LIMIT and OFFSET
            page = 1
            offset = 0
            limit = 15

            if "rp" in rp_dict:
                limit = int(rp_dict.get("rp"))

            if "page" in rp_dict:
                page = int(rp_dict.get("page"))

            offset = limit * (page - 1)

            start = offset
            stop = offset + limit
            audit_q = audit_q.slice(start, stop)

        # we drop here the ORM due to memory consumption
        # and return a resultproxy for row iteration
        stm = audit_q.with_entities(*AuditTable.__table__.columns).statement
        result = db.session.execute(stm).mappings()

        return result

    def getTotal(self, param, AND=True, display_error=True):
        """
        This method returns the total number of audit entries in
        the audit store
        """
        condition = self._buildCondition(param, AND)
        if type(condition).__name__ == "NoneType":
            c = db.session.query(AuditTable).count()
        else:
            c = db.session.query(AuditTable).filter(condition).count()

        return c


def getAsString(data):
    """
    We need to distinguish, if this is an entry after the adding the
    client entry or before. Otherwise the old signatures will break!
    """

    s = (
        "number={}, date={}, action={}, {}, serial={}, {}, user={}, {},"
        " admin={}, {}, {}, server={}, {}, {}"
    ).format(
        str(data.get("id")),
        str(data.get("timestamp")),
        data.get("action"),
        str(data.get("success")),
        data.get("serial"),
        data.get("tokentype"),
        data.get("user"),
        data.get("realm"),
        data.get("administrator"),
        data.get("action_detail"),
        data.get("info"),
        data.get("linotp_server"),
        data.get("log_level"),
        str(data.get("clearance_level")),
    )

    if "client" in data:
        s += ", client={}".format(data.get("client"))
    return s


def getAsBytes(data):
    """
    Return the audit record in a bytes format that can be used
    for signing
    """
    return bytes(getAsString(data), "utf-8")
