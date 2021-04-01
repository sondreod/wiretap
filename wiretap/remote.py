import logging
import subprocess
import time
import traceback

from pssh.exceptions import SessionError
from pssh.clients import SSHClient

from wiretap import collectors
from wiretap.config import settings
from wiretap.schemas import Server

log = logging.getLogger()

ALL_COLLECTORS = [
    collectors.journalctl,
    collectors.cpu,
    collectors.memory,
    collectors.disk,
    collectors.network,
    collectors.files,
    #collectors.Disk,
    #collectors.JournalCtl,
    #collectors.Logs
]


class Remote:
    """ Establish a ssh connection to the *server* and run collectors"""

    def __init__(self, server: Server, config: dict):
        self.server = server
        self.config = config
        self._is_localhost = self.server.host in ['localhost','127.0.0.1']

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


def remote_execution(server, engine):
    remote = Remote(server, engine.config)
    epoch = int(time.time())
    while True:
        clock = int(time.time()) - epoch
        try:
            for c in engine.collectors:
                interval = 60
                if config := engine.config.get(c.__name__.lower()):
                    interval = int(config.get('interval', 60))
                if clock % interval == 0:
                    for response in remote.run(c):
                        for metric in response:
                            engine.add_metric(server, metric)

        except SessionError as e:
            log.error(f"Session error: {e}")
            time.sleep(900)
            remote = Remote(server, engine.config)
        except Exception as e:
            log.error(f"Error in remote execution. ({server.name}). ({type(e)}) {e}")
            log.error(traceback.print_exc())
            break

        if clock > 3600:
            epoch = int(time.time())

        time.sleep(.5)
