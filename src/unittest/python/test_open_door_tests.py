"""open_door test cases"""
import unittest
import json

from secure_all import AccessManager, AccessManagementException, \
    AccessKey, JSON_FILES_PATH, KeysJsonStore, RequestJsonStore


class TestAccessManager(unittest.TestCase):
    """test class for open_door"""
    # pylint: disable=no-member

    @classmethod
    def setUpClass(cls) -> None:
        # first af all, i introduce all value tha I need for the estructural testing
        # remove the old storeKeys
        requests_store = RequestJsonStore()
        keys_store = KeysJsonStore()
        requests_store.empty_store()
        keys_store.empty_store()
        # introduce a key valid and not expired and guest
        my_manager = AccessManager()
        my_manager.request_access_code("51293600N", "Pedro Sanchez",
                                       "Resident", "uc3m@gmail.com", 0)
        my_manager.request_access_code("74009663X", "Emma Irabor",
                                       "Guest", "uc3m@gmail.com", 5)
        rev_guest = my_manager.get_access_key(JSON_FILES_PATH + "revoked_for_open_guest.json")
        rev_res = my_manager.get_access_key(JSON_FILES_PATH + "revoked_for_open_resident.json")
        my_manager.revoke_key(JSON_FILES_PATH + "revoking_for_resident.json")
        my_manager.revoke_key(JSON_FILES_PATH + "revoking_for_guest.json")
        my_manager.request_access_code("05270358T", "Pedro Martin",
                                               "Resident", "uc3m@gmail.com", 0)

        my_manager.request_access_code("53935158C", "Marta Lopez",
                                               "Guest", "uc3m@gmail.com", 5)

        my_manager.get_access_key(JSON_FILES_PATH  + "key_ok.json")

        # introduce a key valid and expiration date = 0 , resident
        my_manager.get_access_key(JSON_FILES_PATH  + "key_ok3_resident.json")

        # introduce a key expirated, I need to change expiration date before to store the key
        my_manager.request_access_code("68026939T", "Juan Perez",
                                       "Guest", "expired@gmail.com", 2)
        # expected result 383a8eb306459919ef0dc819405f16a6
        # We generate the AccessKey for this AccessRequest
        my_key_expirated = AccessKey.create_key_from_file(JSON_FILES_PATH  +
                                                          "key_ok_testing_expired.json")
        # We manipulate the expiration date to obtain an expired AccessKey
        my_key_expirated.expiration_date = 0
        my_key_expirated.store_keys()

        # Method used to set up JSON files that contain access keys
        store_key = JSON_FILES_PATH + 'storeAccessLog.json'
        with open(store_key, "w") as file:
            json.dump([], file)

    def test_key_already_revoked_guest(self):
        """path: key has already been revoked for guest"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.open_door \
                ("c2b67b79fc6c06c0494b079a01e97817c4127ca241db9cdd26ea2b68e69ec117")
        self.assertEqual("key already revoked", c_m.exception.message)

    def test_key_already_revoked_resident(self):
        """path: key has already been revoked for guest"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.open_door \
                ("eaae439f7ad8c55433dc5cb3fae3f4235dc2a490fe70c7adb5fc9eef41b3f166")
        self.assertEqual("key already revoked", c_m.exception.message)

    def test_open_door_bad_key_regex(self):
        """path: regex is not valid , key length is 63 chars"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.open_door\
                ("cc161c01a4bcca82e841b3446e2a3edb3539d72a3a7ec40a07d236998482906")
        self.assertEqual("key invalid", c_m.exception.message)

    def test_open_door_good(self):
        """path: regex ok , key is found , key is not expired, guest"""
        my_key = AccessManager()
        result = my_key.open_door\
            ("de000a04f3a9b1d15b07e38b166f00f3fb1bf46533f32ac37156faf43e47f722")
        self.assertEqual(True, result)

    def test_open_door_resident(self):
        """Tests if key already exists"""
        #path: regex ok, key is found, expiration date is 0, resident
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.open_door\
                ("de000a04f3a9b1d15b07e38b166f00f3fb1bf46533f32ac37156faf43e47f722")
        self.assertEqual("Access already logged", c_m.exception.message)

    def test_open_door_bad_key_is_not_found(self):
        """path: regex ok, key is not found"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.open_door\
                ("fff00d78646ed41a91d60ec2fc1ed326238e510134ca52e5d9b1de5cbdf2b8ab")

        self.assertEqual("key is not found or is expired", c_m.exception.message)

    def test_open_door_bad_key_is_expired(self):
        """Expired key generated in the SetUpClass method"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.open_door\
                ("459063166d5a8e38ac493d4f523e31cca39bdc2c523d12dc08cae4a983224495")

        self.assertEqual("key is not found or is expired", c_m.exception.message)

if __name__ == '__main__':
    unittest.main()
