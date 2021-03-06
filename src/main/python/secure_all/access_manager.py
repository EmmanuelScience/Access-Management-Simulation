"""Module AccessManager with AccessManager Class """

from secure_all.data.access_key import AccessKey
from secure_all.data.access_request import AccessRequest
from secure_all.data.access_log import AccessLog
from secure_all.data.revoke_key import RevokeKey


class AccessManager:
    """AccessManager class, manages the access to a building implementing singleton """
    # pylint: disable=too-many-arguments,no-self-use,invalid-name, too-few-public-methods
    class __AccessManager:
        """Class for providing the methods for managing the access to a building"""

        @staticmethod
        def request_access_code(id_card, name_surname, access_type, email_address, days):
            """ this method give access to the building"""
            my_request = AccessRequest(id_card, name_surname, access_type, email_address, days)
            my_request.store_request()
            return my_request.access_code

        @staticmethod
        def get_access_key(keyfile):
            """Returns the access key for the access code & dni received in a json file"""
            my_key = AccessKey.create_key_from_file(keyfile)
            my_key.store_keys()
            return my_key.key

        @staticmethod
        def open_door(key):
            """Opens the door if the key is valid an it is not expired"""
            created_key = AccessKey.create_key_from_id(key)
            check_valid = created_key.is_valid()
            access_log = AccessLog(key)
            access_log.store_log()
            return check_valid

        @staticmethod
        def revoke_key(keyfile):
            """Revokes a given key"""
            key = RevokeKey.create_key_from_file_for_revoke(keyfile)
            return key.revoke_key()

    __instance = None

    def __new__(cls):
        if not AccessManager.__instance:
            AccessManager.__instance = AccessManager.__AccessManager()
        return AccessManager.__instance
