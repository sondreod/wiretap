import json
from pathlib import Path
from wiretap.config import settings


def read_config(self, prop):
    path = Path(settings.base_path, prop)
    if not path.is_file():
        self._write_config(prop, [])
    with open(path, 'r') as fd:
        return json.load(fd)


def write_config(self, prop, data):
    with open(Path(settings.base_path, prop), 'w') as fd:
        json.dump(data, fd)


def read_file(self, prop):
    path = Path(settings.base_path, prop)
    if not path.is_file():
        self._write_file(prop, '')
    with open(path, 'r') as fd:
        return fd.read().splitlines()


def append_file(self, prop, data: str):
    with open(Path(settings.base_path, prop), 'a') as fd:
        fd.writelines(data)


def write_file(self, prop, data: str):
    with open(Path(settings.base_path, prop), 'w') as fd:
        fd.writelines(data)

