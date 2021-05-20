from datetime import datetime
from secure_all.data.attributes.attribute_key import Key
from secure_all.data.attributes.attribute_revocation import Revocation
from secure_all.data.attributes.attribute_reason import Reason
from secure_all.parser.revoke_json_parser import RevokeJsonParser
from secure_all.storage.keys_json_store import KeysJsonStore
from secure_all.storage.revoke_json_store import RevokeJsonStore
from secure_all.exception.access_management_exception import AccessManagementException
from secure_all.data.access_key import AccessKey

TEST_TIME = datetime.timestamp(datetime.utcnow())


class RevokeKey:
    def __init__(self, key, revocation, reason):
        self.__key = Key(key).value
        self.__revocation = Revocation(revocation).value
        self.__reason = Reason(reason).value

    def revoke_key(self):
        key_object = AccessKey.create_key_from_id(self.__key)
        print(key_object.revoked)
        if key_object.expiration_date != 0 and key_object.expiration_date <= TEST_TIME:
            raise AccessManagementException("Key already expired")
        if key_object.get_revoked(self.__key):
            raise AccessManagementException("Key already revoked")
        key_object.revoked = True
        key_object.revocation = self.__revocation
        key_object.reason = self.__reason
        print(key_object.revoked)
        revoke_store = RevokeJsonStore()
        revoke_store.replace_item(self.__key, key_object.store())
        return key_object.emails_to_str()

    @classmethod
    def create_key_from_file_for_revoke(cls, key_file):
        """Class method from creating an instance of AccessKey
        from the content of a file according to RF2"""
        revoke_key_items = RevokeJsonParser(key_file).json_content
        keys_store = KeysJsonStore()
        key_object = Key(revoke_key_items[RevokeJsonParser.KEY])
        key_dict = keys_store.find_item(key_object.value)
        if key_dict is None:
            raise AccessManagementException("key is not found or is expired")
        return cls(revoke_key_items[RevokeJsonParser.KEY],
                   revoke_key_items[RevokeJsonParser.REVOCATION],
                   revoke_key_items[RevokeJsonParser.REASON])
