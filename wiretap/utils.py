import json
from typing import List
from pathlib import Path
from wiretap.config import settings
from pydantic import parse_file_as
from wiretap.schemas import Server

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


def write_config(prop, data):
    with open(Path(settings.base_path, prop), 'w') as fd:
        json.dump(data, fd)


def read_file(prop):
    path = Path(settings.base_path, prop)
    if not path.is_file():
        write_file(prop, '')
    with open(path, 'r') as fd:
        return fd.read().splitlines()


def append_file(prop, data: str):
    with open(Path(settings.base_path, prop), 'a') as fd:
        fd.writelines(data)


def write_file(prop, data: str):
    with open(Path(settings.base_path, prop), 'w') as fd:
        fd.writelines(data)
