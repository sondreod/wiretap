import logging
import subprocess
from pssh.clients import SSHClient

from wiretap.config import settings
from wiretap.schemas import Server

log = logging.getLogger()


class Remote:
    """ Establish a ssh connection to the *server* and run collectors"""

    def __init__(self, server: Server, config: dict):
        self.server = server
        self.config = config
        self._is_localhost = self.server.host in ['localhost', '127.0.0.1']

        if not self._is_localhost:
            self._establish_connection()

    def run(self, collector):
        """ Executes the *collector* on the remote, using the config from the *server*."""

        config = self._get_config_for_collector(collector)

        for command, aggregator in collector(config):
            text_response = self._run_command(command)
            yield aggregator(text_response, config)

    def _run_command(self, command):
        if not self._is_localhost:
            server_response = self.client.run_command(command)
            if stderr := list(server_response.stderr):
                log.error(stderr)
            return server_response.stdout
        else:
            return (x for x in subprocess.check_output(command, shell=True, text=True).splitlines())

    def _establish_connection(self):
        self.client = SSHClient(self.server.host,
                                user=self.server.username,
                                pkey=settings.pkey_path)
    def _get_config_for_collector(self, collector):
        config = self.config.get(collector.__name__.lower()) or {}
        config['name'] = self.server.name
        return config
