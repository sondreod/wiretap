import sys
import time
import logging
import threading

from datetime import datetime
from enum import Enum

from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS

import uvicorn

from wiretap.remote import remote_execution, ALL_COLLECTORS
from wiretap.schemas import Metric
from wiretap.config import settings
from wiretap.health import health_check, certificate_check
from wiretap.utils import (
    read_config,
    read_inventory,
    get_hashes,
    set_hashes,
    append_file,
    check_files,
)

logging.basicConfig(level=logging.ERROR, format="%(asctime)s / %(name)s: %(message)s")
log = logging.getLogger("root")


class MODE(Enum):
    NORMAL = 1
    CONFIG = 2


class Wiretap:
    def __init__(self, collectors=None):
        if not collectors:
            collectors = ALL_COLLECTORS
        self.collectors = collectors
        self._startup_check()
        self.hashes = get_hashes()
        self.config = read_config()
        self.inventory = read_inventory()
        self.metrics = []
        self.diffs = {}

        self.client = InfluxDBClient(
            url=settings.INFLUX_HOST, token=settings.INFLUX_TOKEN
        )
        self.write_api = self.client.write_api(write_options=SYNCHRONOUS)
        self.query_api = self.client.query_api()
        self.bucket_api = self.client.buckets_api()
        self._db_check()

        self.diff_lock = threading.Lock()
        self.metric_lock = threading.Lock()
        self.threads = list()

        self.RUNMODE = MODE.NORMAL

        welcome = "\nWiretap:\n\nYour inventory:\n"
        for item in self.inventory:
            welcome += f"   {item}\n"
        log.error(welcome)

        self.start_server_threads()

    def start_server_threads(self):
        for server in self.inventory:
            server_thread = threading.Thread(
                target=remote_execution,
                args=(server, self),
                name=f"thread_{server.name}",
                daemon=True,
            )
            self.threads.append(server_thread)
            server_thread.start()

    def aggregate_diff(self, key, value):
        last = self.diffs.get(key)
        with self.diff_lock:
            self.diffs[key] = value  # Trust no one
        if last:
            return value - last

    def add_metric(self, server, metric):
        log.debug(f"add_metric {metric}")
        measurement = field_name = metric.tag
        if name_tuple := metric.tag.split("_", 1):
            if len(name_tuple) == 2:
                measurement, field_name = name_tuple

        if measurement in ["network"]:
            metric.value = self.aggregate_diff(
                server.name + measurement + field_name, metric.value
            )
            if not metric.value:
                return None

        metric.name = server.name
        point = (
            Point(measurement)
            .tag("name", metric.name)
            .tag("agg_type", metric.agg_type)
            .field(field_name, metric.value)
            .time(datetime.utcfromtimestamp(metric.time), WritePrecision.S)
        )

        if self.RUNMODE is MODE.NORMAL:
            if self.add_hash(hash(str(point.__dict__))):
                with self.metric_lock:
                    self.add_point_to_db(point)
                    self.metrics.append(metric.json())
        else:
            print(metric.json())

    def add_hash(self, hash: int):
        """Returns true if hash is new, otherwise false. New hashes are added to the list"""
        if hash in self.hashes:
            return False
        self.hashes.add(hash)
        return True

    def add_point_to_db(self, point):
        self.write_api.write(settings.INFLUX_BUCKET_PREFIX, settings.INFLUX_ORG, point)

    def append_metrics(self):
        print(f"Appending {len(self.metrics)} metrics")
        with self.metric_lock:
            append_file(settings.metric_file, self.metrics)
            self.metrics = []

    def _startup_check(self):
        check_files()

    def _db_check(self):
        buckets = [x.name for x in self.bucket_api.find_buckets().buckets]
        assert settings.INFLUX_BUCKET_PREFIX in buckets

        """ Fuckd library
        if settings.INFLUX_BUCKET_PREFIX not in buckets:
            self.bucket_api.create_bucket(settings.INFLUX_BUCKET_PREFIX,
                                          retention_rules=BucketRetentionRules(type='expire', every_seconds=100000))
        if settings.INFLUX_BUCKET_PREFIX+'_downsampled' not in buckets:
            bucket = Bucket(name='ffdidd', retention_rules=BucketRetentionRules(type='expire', every_seconds=10000))
            self.bucket_api.create_bucket(bucket)
        """


def run_webserver():
    uvicorn.run("web.web:app", host="127.0.0.1", port=1337, workers=4)


def run_main():
    engine = Wiretap()

    if sys.argv[-1] == "config":
        engine.RUNMODE = MODE.CONFIG
        new_collectors = []
        for collector in engine.config:
            for col in ALL_COLLECTORS:
                if collector == col.__name__:
                    new_collectors.append(col)

        engine = Wiretap(collectors=new_collectors)

    def main_loop(engine):
        while True:
            try:
                if engine.RUNMODE is MODE.NORMAL:
                    for server in engine.inventory:
                        health_obj = health_check(server.host)
                        engine.add_metric(
                            server,
                            Metric(
                                tag="health_http_status",
                                time=int(time.time()),
                                value=health_obj.http_status,
                                unit="boolean",
                            ),
                        )
                        engine.add_metric(
                            server,
                            Metric(
                                tag="health_packet_loss",
                                time=int(time.time()),
                                value=health_obj.packet_loss,
                                unit="%",
                            ),
                        )
                        certificate_obj = certificate_check(server.host)
                        if certificate_obj:
                            engine.add_metric(
                                server,
                                Metric(
                                    tag="certificate_expires_at",
                                    time=int(time.time()),
                                    value=certificate_obj.expires_at,
                                    unit="timestamp",
                                ),
                            )
                            engine.add_metric(
                                server,
                                Metric(
                                    tag="certificate_expires_in",
                                    time=int(time.time()),
                                    value=certificate_obj.expires_in,
                                    unit="s",
                                ),
                            )
                        if health_obj.rtt:
                            engine.add_metric(
                                server,
                                Metric(
                                    tag="health_rtt",
                                    time=int(time.time()),
                                    value=health_obj.rtt,
                                    unit="ms",
                                ),
                            )

                    for thread in engine.threads:
                        if not thread.is_alive():
                            log.error(f"{thread.name} has stopped!")
                    set_hashes(engine.hashes)
                    engine.append_metrics()
                    for _ in range(10):
                        time.sleep(1)
            except KeyboardInterrupt:
                return

    main_loop_thread = threading.Thread(
        target=main_loop, args=(engine,), name=f"thread_main"
    )
    engine.threads.append(main_loop_thread)

    main_loop_thread.start()

    if sys.argv[-1] == "web":
        run_webserver()

    main_loop_thread.join()
    exit()

    for thread in engine.threads:  # todo: Gracefull join threads?
        thread.join()


if __name__ == "__main__":
    run_main()
