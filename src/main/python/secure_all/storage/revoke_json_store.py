"""Implements the RequestsJSON Store"""
from secure_all.storage.json_store import JsonStore
from secure_all.cfg.access_manager_config import JSON_FILES_PATH


class RevokeJsonStore:
    """Extends JsonStore"""

    class __RevokeJsonStore(JsonStore):
        """Used for the singleton"""
        # pylint: disable=invalid-name
        ID_FIELD = '_AccessKey__key'
        _FILE_PATH = JSON_FILES_PATH + "storeKeys.json"
        _ID_FIELD = ID_FIELD

    __instance = None

    def __new__(cls):
        if not RevokeJsonStore.__instance:
            RevokeJsonStore.__instance = RevokeJsonStore.__RevokeJsonStore()
        return RevokeJsonStore.__instance

    def __getattr__(self, name):
        return getattr(self.__instance, name)

    def __setattr__(self, name, valor):
        return setattr(self.__instance, name, valor)
