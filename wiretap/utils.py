import json
from pathlib import Path
from wiretap.config import settings


def read_config(prop):
    path = Path(settings.base_path, prop)
    if not path.is_file():
        write_config(prop, [])
    with open(path, 'r') as fd:
        return json.load(fd)


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