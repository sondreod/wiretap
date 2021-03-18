## Wiretap

###### Agentless health and log aggregation for unix systems

This is work in progress.

Simple agentless metric and log collector for Debian based systems without the need for sudo on collected system.

#### Collectors for
- CPU utilization
- Disk usage
- Memory usage
- Network activity
- JournalCtl (in progress)
- Top processes by cpu and memory (todo)

### Server install
```bash
sudo apt install influxdb, python-influxdb, openssh-server
```


### Development

Compile to binary
```bash
source venv/binv/activate
python3.8 -m nuitka --plugin-enable=pylint-warnings  --plugin-enable=gevent  --prefer-source-code --include-module=gevent.greenlet main.py --onefile
```

### Ideas and links
- [Luminare for automatic anomaly detection](https://zillow.github.io/luminaire/tutorial/dataprofiling.html)
- [Downsampling metrics](https://www.influxdata.com/blog/downsampling-influxdb-v2-0/)
