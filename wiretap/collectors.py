import re
import json

from wiretap.schemas import Metric
from wiretap import schemas


class Memory:
    command = r"date +%s && free -m"

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
    command = r"df --output=avail,used,pcent,target -BM | egrep '/$' && date +%s"

    @staticmethod
    def run(x, config=None):
        df_output, timestamp = list(x)
        avail, used, timestamp =\
            map(int, [*re.match(r'(\d{3,20})M\s+(\d{3,20})M.+', df_output).groups(),
                     timestamp])
        return [
            Metric(tag='diskspace_total', time=timestamp, value=avail, unit='MB'),
            Metric(tag='diskspace_used', time=timestamp, value=used, unit='MB'),
            Metric(tag='diskspace_free', time=timestamp, value=avail-used, unit='MB'),
            Metric(tag='diskspace_percent', time=timestamp, value=round(used/avail, 2), unit='%')
        ]


class Processes:
    command = r"date +%s && ps -A"

    @staticmethod
    def run(x, config=None):
        timestamp = next(x)
        for line in x:
            if line.endswith(' nginx'):
                yield Metric(tag='process', time=timestamp, value='nginx', unit='process')


class Cpu:
    command = r"date +%s && lscpu && uptime"

    @staticmethod
    def run(x, config=None):
        timestamp = next(x)
        cpus = 0
        for line in x:
            if line.startswith('CPU(s):'):
                cpus = int(line[-4:])
        cpu_averages = map(float, line.split('load average: ')[1].replace(',', '.').split('. '))
        avg_1, avg_5, avg_15 = map(lambda x: x/cpus, cpu_averages)
        assert 0 <= avg_1 <= 1
        return [
            Metric(tag='cpu_usage', time=timestamp, value=avg_1, unit='%'),
            Metric(tag='cpu_free', time=timestamp, value=1-avg_1, unit='%'),
            Metric(tag='cpu_cores', time=timestamp, value=cpus, unit='%'),
        ]


class Network:
    command = r"date +%s && ip -s link"

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
                yield Metric(tag=f'network_{nic_name}_rx_bytes', time=timestamp, value=rx, unit='bytes')
                yield Metric(tag=f'network_{nic_name}_rx_packets', time=timestamp, value=packets, unit='packets')
                yield Metric(tag=f'network_{nic_name}_rx_errors', time=timestamp, value=errors, unit='errors')
                yield Metric(tag=f'network_{nic_name}_rx_dropped', time=timestamp, value=dropped, unit='packets')

            tx, packets, errors, dropped, carrier, collsns = \
                map(lambda x: int(x)/60, re.match("\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)", tx_line).groups())
            if tx > 0:
                yield Metric(tag=f'network_{nic_name}_tx_bytes', time=timestamp, value=tx, unit='bytes')
                yield Metric(tag=f'network_{nic_name}_tx_packets', time=timestamp, value=packets, unit='packets')
                yield Metric(tag=f'network_{nic_name}_tx_errors', time=timestamp, value=errors, unit='errors')
                yield Metric(tag=f'network_{nic_name}_tx_dropped', time=timestamp, value=dropped, unit='packets')

class JournalCtl:
    command = r"journalctl -n 1000 -o json --no-pager"

    @staticmethod
    def run(x, config=None):
        log_records = [schemas.LogRecord(
            **json.loads(x)
        ) for x in x]

        for line in log_records:
            return None
            for cfg in config:
                "^New session \d+ of user (?P<value>[a-z]+)"
                m = re.match(cfg.get('regex'), line.message)
                if m:
                    m = m.groupdict()
                    print(m.get('value'))
                    yield Metric(time=line.timestamp,
                                 tag=m.get('tag', cfg.get('tag')),
                                 unit=m.get('unit', cfg.get('unit')),
                                 value=m.get('value', cfg.get('value')))
        return []

