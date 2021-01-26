import json
from typing import List
from pathlib import Path
from wiretap.config import settings
from pydantic import parse_file_as
from wiretap.schemas import Server


def keyvalue_get(key: str):
    path = Path(settings.base_path, 'keyvalue.json')
    if path.is_file():
        with open(path, 'r') as fd:
            data = json.load(fd)
            return data.get(key)
    return False


def keyvalue_set(key: str, value: str):
    path = Path(settings.base_path, 'keyvalue.json')
    data = {}
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


def read_file(filename):
    path = Path(settings.base_path, filename)
    if not path.is_file():
        write_file(filename, '')
    with open(path, 'r') as fd:
        return fd.read().splitlines()


def append_file(filename, data: str):
    with open(Path(settings.base_path, filename), 'a') as fd:
        fd.writelines(data)


def write_file(filename, data: str):
    with open(Path(settings.base_path, filename), 'w') as fd:
        fd.writelines(data)
