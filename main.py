import logging
import uuid
import threading
import time

from datetime import datetime

from pssh.exceptions import SessionError
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS

from wiretap.health import health_check
from wiretap import schemas
from wiretap.config import settings
from wiretap.remote import Remote
from wiretap import collectors
from wiretap.schemas import Metric
from wiretap.utils import read_file, read_config, write_config, append_file, write_file

logging.basicConfig(level=logging.ERROR, format='%(asctime)s / %(name)s: %(message)s')
log = logging.getLogger("root")

ALL = [collectors.Cpu,
       collectors.Memory,
       collectors.Network,
       collectors.Disk,
       #collectors.JournalCtl
       #collectors.Files
       ]

inventory = [
    schemas.Server(name="Test1", host="192.168.1.127", username="ubuntu"),
    #schemas.Server(name="localhost", host="localhost", username="ubuntu"),
]


class Wiretap:

    def __init__(self):
        self.hashes = set(read_config(self, 'hashes'))
        self.logs = read_file(self, 'logs')
        self.config = read_config(self, 'config')
        self.metrics = []
        self.client = InfluxDBClient(url="http://localhost:8086", token=settings.INFLUX_TOKEN)
        self.write_api = self.client.write_api(write_options=SYNCHRONOUS)
        self.diffs = {}
        self.diff_lock = threading.Lock()
        self.file_lock = threading.Lock()

    def aggregate_diff(self, key, value):
        last = self.diffs.get(key)
        with self.diff_lock:
            self.diffs[key] = value  # Trust no one
        if last:
            return value - last

    def add_metric(self, server, metric):
        measurement, field_name = metric.tag.split('_', 1)
        if measurement in ['network']:
            metric.value = self.aggregate_diff(server.name+measurement+field_name, metric.value)
            if not metric.value:
                return None
        point = Point(measurement) \
            .tag("name", server.name) \
            .field(field_name, float(metric.value)) \
            .time(datetime.utcfromtimestamp(metric.time), WritePrecision.S)

        if self.add_hash(hash(str(point.__dict__))):
            self.add_point_to_db(point)

    def add_hash(self, hash: int):
        if hash in self.hashes:
            return False
        self.hashes.add(hash)
        with self.file_lock:
            write_config(self, 'hashes', list(self.hashes))
        return True

    def add_point_to_db(self, point):
        self.write_api.write(settings.INFLUX_BUCKET, settings.INFLUX_ORG, point)


if __name__ == '__main__':

    def remote_execution(server, engine):

        remote = Remote(server, engine.config)
        collector_objects = ALL
        while True:
            try:
                for c in collector_objects:
                    for metric in remote.run(c):
                        engine.add_metric(server, metric)
                time.sleep(settings.INTERVAL)
            except SessionError as e:
                log.error(f"Session error: {e}")
                time.sleep(900)
                remote = Remote(server, engine.config)


    engine = Wiretap()
    engine.add_hash(int(uuid.uuid4()))

    threads = list()

    for server in inventory:
        x = threading.Thread(target=remote_execution, args=(server, engine), daemon=True)
        threads.append(x)
        x.start()

    while True:
        for server in inventory:
            health_obj = health_check(server.host)
            engine.add_metric(server, Metric(tag='health_http_status', time=int(time.time()), value=health_obj.http_status, unit='boolean'))
            engine.add_metric(server, Metric(tag='health_packet_loss', time=int(time.time()), value=health_obj.packet_loss, unit='percent'))
            engine.add_metric(server, Metric(tag='health_rtt', time=int(time.time()), value=health_obj.rtt, unit='ms'))
            time.sleep(settings.INTERVAL)

    for thread in threads:  # todo: Gracefull join threads?
        thread.join()