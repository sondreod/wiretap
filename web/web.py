import json

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse

from wiretap.utils import read_config, read_inventory, read_reverse_order, filestats
from wiretap.config import settings

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
        if n <= 100 and line:
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


