import json
import threading

from typing import List
from pathlib import Path
from wiretap.config import settings
from pydantic import parse_file_as
from wiretap.schemas import Server


lock = threading.Lock()

def keyvalue_get(key: str):
    path = Path(settings.base_path, 'keyvalue.json')
    if path.is_file():
        with lock:
            with open(path, 'r') as fd:
                data = json.load(fd)
                return data.get(key)
    return False


def keyvalue_set(key: str, value: str):
    path = Path(settings.base_path, 'keyvalue.json')
    data = {}
    with lock:
        if path.is_file():
            with open(path, 'r') as fd:
                data = json.load(fd)
        data[key] = value
        with open(path, 'w') as fd:
            json.dump(data, fd, indent=2)


def read_inventory():
    try:
        return parse_file_as(List[Server], settings.inventory_file)
    except Exception:
        raise RuntimeError(f'Could not read inventory file: {settings.inventory_file}')


def read_config():
    try:
        with open(settings.config_file, 'r') as fd:
            return json.load(fd)
    except Exception:
        raise RuntimeError(f'Could not read config file: {settings.config_file}')

def get_hashes():
    if not Path(settings.hash_file).is_file():
        set_hashes([])
    try:
        with open(settings.hash_file, 'r') as fd:
            return set(json.load(fd))
    except Exception:
        raise RuntimeError(f'Could not read hash file: {settings.hash_file}')


def set_hashes(hashes: list):
    with open(settings.hash_file, 'w') as fd:
        json.dump(list(hashes), fd)

def read_file(path):
    if not Path(path).is_file():
        write_file(path, [''])
    with open(path, 'r') as fd:
        return fd.read().splitlines()


def append_file(path, data: list):
    if not Path(path).is_file():
        write_file(path, [''])
    with open(path, 'a') as fd:
        data = map(lambda x: x+'\n', data)
        fd.writelines(data)


def write_file(path, data: list):
    with open(path, 'w') as fd:
        fd.writelines(data)


def check_files():
    """ Creates required files if not present """
    if not Path(settings.inventory_file).is_file():
        with open(settings.inventory_file, 'w') as fd:
            json.dump([{"name": "Localhost", "host": "127.0.0.1"}], fd, indent=2)
    if not Path(settings.hash_file).is_file():
        with open(settings.hash_file, 'w') as fd:
            json.dump([], fd)
    if not Path(settings.config_file).is_file():
        with open(settings.config_file, 'w') as fd:
            json.dump({}, fd)
    if not Path(settings.metric_file).is_file():
        with open(settings.config_file, 'w') as fd:
            fd.write("")
