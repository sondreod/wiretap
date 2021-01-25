import re
import requests
import subprocess

from typing import Tuple
from collections import namedtuple
from pydantic import validate_arguments, AnyHttpUrl


HealthResponse = namedtuple('HealthResponse', "http_status packet_loss rtt")


@validate_arguments
def http(url: AnyHttpUrl, timeout: int = 10) -> bool:
    """ Returns True if get request to url returns a 200 reponse """

    try:
        http_response = requests.get(url, timeout=timeout)
    except requests.exceptions.ConnectionError:
        return False
    return str(http_response.status_code)[0] in ['2', '3']


@validate_arguments
def ping(host: str, count: int = 4, timeout: int = 10) -> Tuple[int, float]:
    """ Ping a host using ICMP, returns tuple with packet loss in percent and round trip time max in ms """


    ping_response = subprocess.Popen(["/bin/ping", f"-c{str(count)}", f"-w{str(timeout)}", host],
                                     stdout=subprocess.PIPE).stdout.read().decode('utf-8')
    packet_loss = int(re.search(r'(\d+)% packet loss', ping_response).groups()[0])
    try:
        rtt = float(re.search(r'(?:(?:[0-9]*[.])?[0-9]+)\/'
                              r'(?:(?:[0-9]*[.])?[0-9]+)\/'
                              r'((?:[0-9]*[.])?[0-9]+)\/(?:(?:[0-9]*[.])?[0-9]+) ms', ping_response).groups()[0])
    except AttributeError:
        rtt = None

    return packet_loss, rtt


@validate_arguments
def health_check(host: str) -> HealthResponse:
    return HealthResponse(http(f"http://{host}", timeout=1), *ping(host, count=1, timeout=5))


if __name__ == '__main__':
    print(health_check('http://127.1.0.1:8000'))
    print(health_check('http://127.0.0.1:8000'))
    print(health_check('http://127.0.0.1:8002'))




