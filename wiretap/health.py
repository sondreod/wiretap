import re
import ssl
import socket
import datetime
import requests
import subprocess

from typing import Tuple
from collections import namedtuple
from pydantic import validate_arguments, AnyHttpUrl


HealthResponse = namedtuple("HealthResponse", "http_status packet_loss rtt")
CertificateResponse = namedtuple("CertificateResponse", "expires_in expires_at")


@validate_arguments
def http(url: AnyHttpUrl, timeout: int = 10) -> bool:
    """Returns True if get request to url returns a 200 reponse"""

    try:
        http_response = requests.get(url, timeout=timeout)
    except requests.exceptions.ConnectionError:
        return False
    return str(http_response.status_code)[0] in ["2", "3"]


@validate_arguments
def ping(host: str, count: int = 4, timeout: int = 10) -> Tuple[int, float]:
    """Ping a host using ICMP, returns tuple with packet loss in percent and round trip time max in ms"""

    ping_response = (
        subprocess.Popen(
            ["/bin/ping", f"-c{str(count)}", f"-w{str(timeout)}", host],
            stdout=subprocess.PIPE,
        )
        .stdout.read()
        .decode("utf-8")
    )
    packet_loss = int(re.search(r"(\d+)% packet loss", ping_response).groups()[0])
    try:
        rtt = float(
            re.search(
                r"(?:(?:[0-9]*[.])?[0-9]+)\/"
                r"(?:(?:[0-9]*[.])?[0-9]+)\/"
                r"((?:[0-9]*[.])?[0-9]+)\/(?:(?:[0-9]*[.])?[0-9]+) ms",
                ping_response,
            ).groups()[0]
        )
    except AttributeError:
        rtt = False

    return packet_loss, rtt


@validate_arguments
def health_check(host: str) -> HealthResponse:
    return HealthResponse(
        http(f"http://{host}", timeout=1), *ping(host, count=1, timeout=5)
    )


def certificate_check(hostname: AnyHttpUrl, timeout: int = 10) -> CertificateResponse:
    """If a certificate is presented, returns number of seconds until it expires, else False

    Params
    ======
    hostname: str
        Hostname to check certificates for, without protocol prefix

    timeout: int, Default 10
        How long to wait for a response from *hostname*

    Returns
    =======
    int
        Seconds until the certificate expires, or False on failure

    """
    ssl_date_fmt = r"%b %d %H:%M:%S %Y %Z"

    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(
            socket.socket(socket.AF_INET),
            server_hostname=hostname,
        )
        conn.settimeout(timeout)

        conn.connect((hostname, 443))
        ssl_info = conn.getpeercert()
        expires = datetime.datetime.strptime(ssl_info["notAfter"], ssl_date_fmt)

        return CertificateResponse(
            int((expires - datetime.datetime.utcnow()).total_seconds()),
            int(expires.timestamp()),
        )

    except ConnectionRefusedError:
        return False
    except socket.gaierror:
        return False
    except ssl.SSLCertVerificationError:
        return False


if __name__ == "__main__":
    print(certificate_check("localhost"))
