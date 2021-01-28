import time
import logging
import threading

from datetime import datetime

from pssh.exceptions import SessionError
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS

from wiretap import collectors
from wiretap.remote import Remote
from wiretap.schemas import Metric
from wiretap.config import settings
from wiretap.health import health_check
from wiretap.utils import read_config, read_inventory, get_hashes, set_hashes, append_file

logging.basicConfig(level=logging.ERROR, format='%(asctime)s / %(name)s: %(message)s')
log = logging.getLogger("root")

ALL_COLLECTORS = [collectors.Cpu,
                  collectors.Memory,
                  collectors.Network,
                  collectors.Disk,
                  collectors.JournalCtl,
                  collectors.Files,
                  #collectors.Logs,
                  ]


class Wiretap:

    def __init__(self):
        self.hashes = get_hashes()
        self.config = read_config()
        self.inventory = read_inventory()
        self.metrics = []
        self.client = InfluxDBClient(url=settings.INFLUX_HOST, token=settings.INFLUX_TOKEN)
        self.write_api = self.client.write_api(write_options=SYNCHRONOUS)
        self.diffs = {}
        self.diff_lock = threading.Lock()
        self.file_lock = threading.Lock()

        welcome = ("\nWiretap:\n\nYour inventory:\n")
        for item in self.inventory:
            welcome += f"   {item}\n"
        log.error(welcome)

    def aggregate_diff(self, key, value):
        last = self.diffs.get(key)
        with self.diff_lock:
            self.diffs[key] = value  # Trust no one
        if last:
            return value - last

    def add_metric(self, server, metric):
        measurement = field_name = metric.tag
        if name_tuple := metric.tag.split('_', 1):
            if len(name_tuple) == 2:
                measurement, field_name = name_tuple

        if measurement in ['network']:
            metric.value = self.aggregate_diff(server.name+measurement+field_name, metric.value)
            if not metric.value:
                return None
        point = Point(measurement) \
            .tag("name", server.name) \
            .tag("agg_type", metric.agg_type) \
            .field(field_name, metric.value) \
            .time(datetime.utcfromtimestamp(metric.time), WritePrecision.S)

        if self.add_hash(hash(str(point.__dict__))):
            self.add_point_to_db(point)
            self.metrics.append(metric.json())
        print(metric)

    def add_hash(self, hash: int):
        """ Returns true if hash is new, otherwise false. New hashes are added to the list"""
        if hash in self.hashes:
            return False
        self.hashes.add(hash)
        return True

    def add_point_to_db(self, point):
        self.write_api.write(settings.INFLUX_BUCKET, settings.INFLUX_ORG, point)

    def append_metrics(self):
        print(f'Appending {len(self.metrics)} metrics')
        append_file(settings.metric_file, self.metrics)
        self.metrics = []


if __name__ == '__main__':

    def remote_execution(server, engine):
        remote = Remote(server, engine.config)
        while True:
            try:
                for c in ALL_COLLECTORS:
                    # todo: Check if config interval in current clock cycle
                    if response := remote.run(c):
                        for metric in response:
                            engine.add_metric(server, metric)
            except SessionError as e:
                log.error(f"Session error: {e}")
                time.sleep(900)
                remote = Remote(server, engine.config)
            except Exception as e:
                log.error(f"Error in remote execution. ({server.name}). ({type(e)}) {e}")

            time.sleep(settings.COLLECTION_INTERVAL)


    engine = Wiretap()
    threads = list()

    for server in engine.inventory:
        x = threading.Thread(target=remote_execution,
                             args=(server, engine),
                             name=f"thread_{server.name}",
                             daemon=True)
        threads.append(x)
        x.start()

    while True:
        for server in engine.inventory:
            health_obj = health_check(server.host)
            engine.add_metric(server, Metric(tag='health_http_status', time=int(time.time()), value=health_obj.http_status, unit='boolean'))
            engine.add_metric(server, Metric(tag='health_packet_loss', time=int(time.time()), value=health_obj.packet_loss, unit='percent'))
            engine.add_metric(server, Metric(tag='health_rtt', time=int(time.time()), value=health_obj.rtt, unit='ms'))
        for thread in threads:
            if not thread.is_alive():
                log.error(f"{thread.name} has stopped!")
        set_hashes(engine.hashes)
        engine.append_metrics()
        time.sleep(settings.HEALTH_INTERVAL)

    for thread in threads:  # todo: Gracefull join threads?
        thread.join()
