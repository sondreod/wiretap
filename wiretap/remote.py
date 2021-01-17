from pssh.clients import SSHClient

from wiretap import collectors
from wiretap.config import settings
from wiretap.schemas import Server



class Remote:
    """ Establish a ssh connection to the *server* and run collectors"""

    def __init__(self, server: Server, config: dict):
        self.server = server
        self.config = config

        self._establish_connection()

    def run(self, collector):
        server_response = self.client.run_command(collector.command)
        stderr = list(server_response.stderr)
        if stderr:
            print(stderr)
        return collector.run(server_response.stdout,
                             self.config.get(collector.__name__.lower()))

    def _establish_connection(self):
        self.client = SSHClient(self.server.host,
                                user=self.server.username,
                                pkey=settings.pkey_path)


if __name__ == '__main__':

    remote = Remote(Server(name="Test1", host="192.168.1.127"), {})
    collector_objects = [collectors.JournalCtl]
    for c in collector_objects:
        print(list(remote.run(c)))
