import logging
import subprocess
from pssh.clients import SSHClient

from wiretap import collectors
from wiretap.config import settings
from wiretap.schemas import Server

log = logging.getLogger()


class Remote:
    """ Establish a ssh connection to the *server* and run collectors"""

    def __init__(self, server: Server, config: dict):
        self.server = server
        self.config = config

        if not self._is_localhost():
            self._establish_connection()

    def run(self, collector):
        """ Executes the *collector* on the remote, using the config from the *server*."""
        config = self.config.get(collector.__name__.lower())
        if not config:
            config = {}
        config['name'] = self.server.name

        command = collector.command(config)
        if not self._is_localhost():
            server_response = self.client.run_command(command)
            if stderr := list(server_response.stderr):
                log.error(stderr)
            text_response = server_response.stdout
        else:
            text_response = (x for x in subprocess.check_output(command, shell=True, text=True).splitlines())
        return collector.run(text_response, config)

    def _establish_connection(self):
        self.client = SSHClient(self.server.host,
                                user=self.server.username,
                                pkey=settings.pkey_path)

    def _is_localhost(self):
        return self.server.host in ['localhost', '127.0.0.1']
