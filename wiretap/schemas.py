from pydantic import BaseModel, Field
from typing import Callable, Union, Any, Optional


class Server(BaseModel):
    name: str
    host: str = Field(..., regex=r'[a-z0-9\.\-]{3,100}', description='Domain name or IP')
    username: str = Field('ubuntu')


class Record(BaseModel):
    timestamp: int = Field(..., alias='__REALTIME_TIMESTAMP')


class LogRecord(Record):
    message: str = Field(..., alias='MESSAGE')
    transport: str = Field(..., alias='_TRANSPORT')
    hostname: str = Field(..., alias='_HOSTNAME')
    boot_id: str = Field(..., alias='_BOOT_ID')

class Metric(BaseModel):
    tag: str
    time: int
    value: Any
    unit: str
