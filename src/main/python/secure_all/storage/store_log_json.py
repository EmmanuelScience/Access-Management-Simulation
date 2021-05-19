"""Implements the RequestsJSON Store"""
from secure_all.storage.json_store import JsonStore
from secure_all.exception.access_management_exception import AccessManagementException
from secure_all.cfg.access_manager_config import JSON_FILES_PATH



class AccessLogJsonStore():
    """Extends JsonStore"""

    class __AccessLogJsonStore(JsonStore):
        """Used for the singleton"""
        # pylint: disable=invalid-name
        INVALID_ITEM = "key invalid"
        ID_FIELD = '_AccessLog__key'
        KEY_ALREADY_STORED = "Access already logged"
        _FILE_PATH = JSON_FILES_PATH + "storeAccessLog.json"
        _ID_FIELD = ID_FIELD

        def add_item(self, item):
            """Implementing the restrictions related to avoid duplicated access code in the list
            import of AccessRequest must be placed here instead of at the top of the file
            to avoid circular references"""
            #pylint: disable=import-outside-toplevel,cyclic-import
            from secure_all.data.access_log import AccessLog

            if not isinstance(item, AccessLog):
                raise AccessManagementException(self.INVALID_ITEM)

            if not self.find_item(item.key) is None:
                raise AccessManagementException(self.KEY_ALREADY_STORED)

            return super().add_item(item)

    __instance = None

    def __new__(cls):
        if not AccessLogJsonStore.__instance:
            AccessLogJsonStore.__instance = AccessLogJsonStore.__AccessLogJsonStore()
        return AccessLogJsonStore.__instance

    def __getattr__(self, name):
        return getattr(self.__instance, name)

    def __setattr__(self, name, valor):
        return setattr(self.__instance, name, valor)
