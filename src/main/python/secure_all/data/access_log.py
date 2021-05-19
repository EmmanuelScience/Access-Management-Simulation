"""Module representing the access log"""
from datetime import datetime
from secure_all.storage.store_log_json import AccessLogJsonStore


class AccessLog:
    """class representing the access log"""
    def __init__(self, key: str):
        self.__key = key
        just_now = datetime.utcnow()
        self.__access_time = datetime.timestamp(just_now)

    def store(self):
        """function used in the jsonStore"""
        return self.__dict__

    def store_log(self):
        """stores the the access log"""
        log_store = AccessLogJsonStore()
        log_store.add_item(self)

    @property
    def access_time(self):
        """Read-only property that returns the timestamp of the request"""
        return self.__access_time

    @property
    def key(self):
        """Read-only property that returns the key of the request"""
        return self.__key
