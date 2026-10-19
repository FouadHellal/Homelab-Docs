"""Container healthcheck: GET /healthz on the loopback interface only.

Hard-coded host (127.0.0.1) and path; the only inputs are port numbers. HTTPS is tried
without certificate verification because the target is this very process on loopback, which
serves a self-signed certificate in LAN mode.
"""

import http.client
import ssl
from collections.abc import Iterable

LOOPBACK = "127.0.0.1"


def probe(ports: Iterable[tuple[int, bool]], timeout: float = 3.0) -> bool:
    """True as soon as one (port, https) answers 200 to GET /healthz."""
    for port, https in ports:
        if not 1 <= port <= 65535:
            continue
        conn: http.client.HTTPConnection
        if https:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE  # loopback to ourselves, self-signed
            conn = http.client.HTTPSConnection(LOOPBACK, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(LOOPBACK, port, timeout=timeout)
        try:
            conn.request("GET", "/healthz", headers={"Host": "localhost"})
            if conn.getresponse().status == 200:
                return True
        except (OSError, http.client.HTTPException):
            continue
        finally:
            conn.close()
    return False
