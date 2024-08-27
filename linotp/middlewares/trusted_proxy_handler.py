"""
Middleware for Trusted Proxy Handling.

This module provides a middleware class, `TrustedProxyHandler`, designed to manage
requests coming through trusted proxies. The middleware strips proxy information
from incoming requests if the request originates from a trusted proxy. This ensures
that the application processes requests with the correct client information, avoiding
potential issues related to proxy-related headers.

Classes:
    TrustedProxyHandler: Middleware that removes proxy information from requests
                         originating from trusted proxies.

Usage Example:
    from trusted_proxy_handler import TrustedProxyHandler
    from some_wsgi_framework import your_app

    # List of trusted proxies
    trusted_proxies = ["192.168.1.1", "10.0.0.1"]

    # Wrap your WSGI application with the middleware
    app = TrustedProxyHandler(your_app, trusted_proxies)

"""

import logging

from linotp.lib.type_utils import get_ip_address, get_ip_network
from linotp.lib.util import is_addr_in_network

log = logging.getLogger(__name__)


class TrustedProxyHandler:
    """
    This middleware removes the proxy information from the request only if
    it matches the trusted proxies in the settings.
    """

    def __init__(self, app, trusted_proxies):
        self.app = app
        self.trusted_proxies = self._resolve_proxies(trusted_proxies)

    def __call__(self, environ, start_response):
        orig_remote_addr = environ.get("REMOTE_ADDR")

        real_remote_addr = self._get_remote_addr(
            environ.get("HTTP_X_FORWARDED_FOR", "")
        )

        if (
            self._is_address_in_networks_list(
                orig_remote_addr, self.trusted_proxies
            )
            and real_remote_addr
        ):
            environ["REMOTE_ADDR"] = real_remote_addr
            environ.update(
                {"linotp.proxy_fix.orig_remote_addr": orig_remote_addr}
            )

        return self.app(environ, start_response)

    def _get_remote_addr(self, x_forwarded_for: str):
        """Selects the new remote addr from the given list of ips in
        X-Forwarded-For. It picks up the first one, ignoring all the rest of the list
        """

        x_forwarded_for = x_forwarded_for.split(",")
        x_forwarded_for = [
            x for x in [x.strip() for x in x_forwarded_for] if x
        ]
        return x_forwarded_for[0] if x_forwarded_for else None

    def _resolve_proxies(self, proxies):
        """
        Resolve DNS hostnames in the list of proxies to IP addresses.

        Args:
            proxies (list): List of IP addresses, network addresses, or DNS hostnames.

        Returns:
            list: List of resolved IP addresses and network addresses.
        """

        resolved_proxies = []
        for proxy in proxies:
            ip_addr = get_ip_address(proxy) or get_ip_network(proxy)
            if ip_addr:
                resolved_proxies.append(ip_addr)
            else:
                log.warning(
                    f"Disregarding non-supported or bad proxy definition: '{proxy}'. This could also be due to a domain name that could not be resolved"
                )

        return resolved_proxies

    def _is_address_in_networks_list(self, addr, networks):
        """
        Check if the address is in the specified networks list.

        Args:
            addr (str): The IP address to check.
            networks (list): A list of network ranges to check against.

        Returns:
            bool: True if the address is in any of the specified networks, False otherwise.
        """

        return any(
            is_addr_in_network(addr, str(network)) for network in networks
        )