import logging
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

        self._establish_connection()

    def run(self, collector):
        """ Executes the *collector* on the remote, using the config from the *server*."""
        command = self._eval_variables_in_command(collector.command, self.config)
        server_response = self.client.run_command(command)
        stderr = list(server_response.stderr)
        if stderr:
            log.error(stderr)
        return collector.run(server_response.stdout,
                             self.config.get(collector.__name__.lower()))

    def _establish_connection(self):
        self.client = SSHClient(self.server.host,
                                user=self.server.username,
                                pkey=settings.pkey_path)

    @staticmethod
    def _eval_variables_in_command(command, config):
        if config.get('args'):
            for n, arg in enumerate(config.get('args')):
                command.replace(f'arg{n}', arg)
        return command


if __name__ == '__main__':

    remote = Remote(Server(name="Test1", host="192.168.1.127"), {})
    collector_objects = [collectors.JournalCtl]
    for c in collector_objects:
        print(list(remote.run(c)))
