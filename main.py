import json
import time
import logging
import threading
import traceback

from datetime import datetime

import uvicorn
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from pssh.exceptions import SessionError
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS

from wiretap import collectors
from wiretap.remote import Remote
from wiretap.schemas import Metric
from wiretap.config import settings
from wiretap.health import health_check
from wiretap.utils import read_config,read_inventory, get_hashes, set_hashes, append_file, check_files,\
    read_reverse_order, filestats

logging.basicConfig(level=logging.ERROR, format='%(asctime)s / %(name)s: %(message)s')
log = logging.getLogger("root")

ALL_COLLECTORS = [collectors.Cpu,
                  collectors.Memory,
                  collectors.Network,
                  collectors.Disk,
                  collectors.JournalCtl,
                  collectors.Files,
                  #collectors.Logs
                  ]


class Wiretap:

    def __init__(self):
        self._startup_check()
        self.hashes = get_hashes()
        self.config = read_config()
        self.inventory = read_inventory()
        self.metrics = []
        self.diffs = {}

        self.client = InfluxDBClient(url=settings.INFLUX_HOST, token=settings.INFLUX_TOKEN)
        self.write_api = self.client.write_api(write_options=SYNCHRONOUS)
        self.query_api = self.client.query_api()
        self.bucket_api = self.client.buckets_api()
        self._db_check()

        self.diff_lock = threading.Lock()
        self.metric_lock = threading.Lock()


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

        metric.name = server.name
        point = Point(measurement) \
            .tag("name", metric.name) \
            .tag("agg_type", metric.agg_type) \
            .field(field_name, metric.value) \
            .time(datetime.utcfromtimestamp(metric.time), WritePrecision.S)

        if self.add_hash(hash(str(point.__dict__))):
            with self.metric_lock:
                self.add_point_to_db(point)
                self.metrics.append(metric.json())

    def add_hash(self, hash: int):
        """ Returns true if hash is new, otherwise false. New hashes are added to the list"""
        if hash in self.hashes:
            return False
        self.hashes.add(hash)
        return True

    def add_point_to_db(self, point):
        self.write_api.write(settings.INFLUX_BUCKET_PREFIX, settings.INFLUX_ORG, point)

    def append_metrics(self):
        print(f'Appending {len(self.metrics)} metrics')
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

app = FastAPI()
app.mount("/static", StaticFiles(directory="web/static"), name="static")

@app.get("/", response_class=HTMLResponse)
def serve_front():
    with open('web/index.html', 'r') as fd:
        return str(fd.read())

@app.get("/api/inventory")
def serve_inventory():
    inventory = []
    temp = read_inventory()
    for item in temp:
        item = dict(item)
        item["timestamp"] = 0
        inventory.append(item)

    for n, line in enumerate(read_reverse_order(settings.metric_file)):
        if line:
            line = json.loads(line)
            if line.get('tag') == 'health_rtt':
                for server in inventory:
                    if server.get('name') == line.get('name'):
                        if line.get('time') > server['timestamp']:
                            server['timestamp'] = line.get('time')
                            break
        if n > 1000 or all(x.get('timestamp') > 0 for x in inventory):
            break

    return inventory

@app.get("/api/metrics")
def serve_metrics():
    for n, line in enumerate(read_reverse_order(settings.metric_file)):
        if n <= 25:
            if line:
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    pass
        else:
            break

@app.get("/api/config")
def serve_config():
    return read_config()


@app.get("/api/stats")
def serve_stats():
    linecount, filesize = map(int, filestats(settings.metric_file))
    return {
        "metrics_size": filesize,
        "metrics_count": '{:,}'.format(linecount).replace(',',' ')
    }

if __name__ == '__main__':

    def remote_execution(server, engine):
        remote = Remote(server, engine.config)
        epoch = int(time.time())
        while True:
            clock = int(time.time()) - epoch
            try:
                for c in ALL_COLLECTORS:
                    interval = 60
                    if config := engine.config.get(c.__name__.lower()):
                        interval = int(config.get('interval', 60))
                    if clock % interval == 0:
                        if response := remote.run(c):
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


    engine = Wiretap()
    threads = list()

    for server in engine.inventory:
        x = threading.Thread(target=remote_execution,
                             args=(server, engine),
                             name=f"thread_{server.name}",
                             daemon=True)
        threads.append(x)
        x.start()


    def main_loop(engine):
        while True:
            for server in engine.inventory:
                health_obj = health_check(server.host)
                engine.add_metric(server, Metric(tag='health_http_status', time=int(time.time()), value=health_obj.http_status, unit='boolean'))
                engine.add_metric(server, Metric(tag='health_packet_loss', time=int(time.time()), value=health_obj.packet_loss, unit='%'))
                if health_obj.rtt:
                    engine.add_metric(server, Metric(tag='health_rtt', time=int(time.time()), value=health_obj.rtt, unit='ms'))

            for thread in threads:
                if not thread.is_alive():
                    log.error(f"{thread.name} has stopped!")
            set_hashes(engine.hashes)
            engine.append_metrics()
            for _ in range(10):
                time.sleep(1)

    main_loop_thread = threading.Thread(target=main_loop,
                         args=(engine,),
                         name=f"thread_main")
    threads.append(main_loop_thread)
    main_loop_thread.start()

    uvicorn.run("main:app", host='127.0.0.1', port=1337, workers=4)
    main_loop_thread.join()
    exit()

    for thread in threads:  # todo: Gracefull join threads?
        thread.join()
