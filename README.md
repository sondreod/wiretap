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

