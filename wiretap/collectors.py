import re
import json

from wiretap.schemas import Metric
from wiretap.utils import keyvalue_set, keyvalue_get
from wiretap import schemas


class Memory:
    @staticmethod
    def command():
        return r"date +%s && free -m"


    @staticmethod
    def run(x, config=None):
        timestamp = next(x)
        for line in x:
            if line.startswith('Mem:'):
                total, used, free, shared, buffcached, avail = \
                    map(float, re.match("^Mem:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)", line).groups())
                yield Metric(tag='memory_available', time=timestamp, value=avail, unit='MiB')
                yield Metric(tag='memory_used', time=timestamp, value=used, unit='MiB')
                yield Metric(tag='memory_total', time=timestamp, value=total, unit='MiB')
                yield Metric(tag='memory_free', time=timestamp, value=total-used, unit='MiB')
            if line.startswith('Swap:'):
                total, used, free =\
                    map(float, re.match("^Swap:\s+(\d+)\s+(\d+)\s+(\d+)", line).groups())
                yield Metric(tag='swap_used', time=timestamp, value=used, unit='MiB')
                yield Metric(tag='swap_total', time=timestamp, value=total, unit='MiB')
                yield Metric(tag='swap_free', time=timestamp, value=total-used, unit='MiB')

class DiskActivity:
    # cat /proc/diskstats
    # https://www.kernel.org/doc/Documentation/block/stat.txt
    pass

class Disk:
    @staticmethod
    def command():
        return r"df --output=avail,used,pcent,target -BM | egrep '/$' && date +%s"


    @staticmethod
    def run(x, config=None):
        df_output, timestamp = list(x)
        avail, used, timestamp = \
            map(int, [*re.match(r'(\d{3,20})M\s+(\d{3,20})M.+', df_output).groups(),
                      timestamp])
        return [
            Metric(tag='diskspace_total', time=timestamp, value=avail+used, unit='MB'),
            Metric(tag='diskspace_used', time=timestamp, value=used, unit='MB'),
            Metric(tag='diskspace_free', time=timestamp, value=avail, unit='MB'),
            Metric(tag='diskspace_percent', time=timestamp, value=round(used/avail, 2), unit='%')
        ]


class Files:
    @staticmethod
    def command():
        return r"date +%s && ls arg0"

    @staticmethod
    def run(x, config=None):
        timestamp = next(x)

        files = len(x[1:])
        #return Metric(tag='diskspace_percent', time=timestamp, value=round(used/avail, 2), unit='%')


class Processes:
    @staticmethod
    def command():
        return r"date +%s && ps -A"

    @staticmethod
    def run(x, config=None):
        timestamp = next(x)
        for line in x:
            if line.endswith(' nginx'):
                yield Metric(tag='process', time=timestamp, value='nginx', unit='process', agg_type='nop')


class Cpu:
    @staticmethod
    def command():
        return r"date +%s && lscpu && uptime"

    @staticmethod
    def run(x, config=None):
        timestamp = next(x)
        cpus = 0
        for line in x:
            if line.startswith('CPU(s):'):
                cpus = int(line[-4:])
        cpu_averages = map(float, line.split('load average: ')[1].replace(',', '.').split('. '))
        avg_1, avg_5, avg_15 = map(lambda x: x/cpus, cpu_averages)
        try:
            assert 0 <= avg_1 <= 1
        except AssertionError:
            return []
        return [
            Metric(tag='cpu_usage', time=timestamp, value=avg_1, unit='%'),
            Metric(tag='cpu_free', time=timestamp, value=1-avg_1, unit='%'),
            Metric(tag='cpu_cores', time=timestamp, value=cpus, unit='%'),
        ]


class Network:
    @staticmethod
    def command():
        return r"date +%s && ip -s link"

    @staticmethod
    def run(x, config=None):
        timestamp = next(x)
        result = list(x)
        number_of_nics = int(result[-6].split(':')[0])
        for i in range(number_of_nics):
            pos = i*6
            nic_name = result[pos].split(':')[1].strip().lower()
            if nic_name == 'lo':
                continue
            rx_line = result[pos+3]
            tx_line = result[pos+5]
            rx, packets, errors, dropped, overrun, mcast = \
                map(lambda x: int(x)/60, re.match("\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)", rx_line).groups())
            if rx > 0:
                yield Metric(tag=f'network_{nic_name}_rx_bytes', time=timestamp, value=rx, unit='bytes', agg_type='count')
                yield Metric(tag=f'network_{nic_name}_rx_packets', time=timestamp, value=packets, unit='packets', agg_type='count')
                yield Metric(tag=f'network_{nic_name}_rx_errors', time=timestamp, value=errors, unit='errors', agg_type='count')
                yield Metric(tag=f'network_{nic_name}_rx_dropped', time=timestamp, value=dropped, unit='packets', agg_type='count')

            tx, packets, errors, dropped, carrier, collsns = \
                map(lambda x: int(x)/60, re.match("\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)", tx_line).groups())
            if tx > 0:
                yield Metric(tag=f'network_{nic_name}_tx_bytes', time=timestamp, value=tx, unit='bytes', agg_type='count')
                yield Metric(tag=f'network_{nic_name}_tx_packets', time=timestamp, value=packets, unit='packets', agg_type='count')
                yield Metric(tag=f'network_{nic_name}_tx_errors', time=timestamp, value=errors, unit='errors', agg_type='count')
                yield Metric(tag=f'network_{nic_name}_tx_dropped', time=timestamp, value=dropped, unit='packets', agg_type='count')


class JournalCtl:
    @staticmethod
    def command():
        cursor = keyvalue_get('journal_cursor')
        if cursor:
            return f'journalctl -o json --no-pager --output-fields="MESSAGE,_TRANSPORT,_HOSTNAME,_BOOT_ID" --after-cursor="{cursor}"'
        else:
            return f'journalctl -o json --no-pager --output-fields="MESSAGE,_TRANSPORT,_HOSTNAME,_BOOT_ID" -n 100000'

    @staticmethod
    def run(x, config=None):
        log_records = [schemas.LogRecord(
            **json.loads(x)
        ) for x in x]
        if log_records:
            keyvalue_set('journal_cursor', log_records[-1].cursor)
            for l in log_records:
                print(l)


        for line in log_records:
            for rule in config.get('rules'):
                m = re.match(rule.get('regex'), line.message)
                if m:
                    if m := m.groupdict():
                        metric = Metric(tag=rule.get('tag'), time=int(str(line.timestamp)[:-6]))
                        if tag := m.get('tag'):
                            metric.tag = tag
                        if value := m.get('value'):
                            metric.value = value
                        yield metric

