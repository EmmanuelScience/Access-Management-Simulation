
import unittest
from secure_all.data.revoke_key import RevokeKey
from secure_all import AccessManager, AccessManagementException,\
    JSON_FILES_PATH, KeysJsonStore, RequestJsonStore


class MyTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        """Removing the Stores and creating required AccessRequest for testing"""
        # pylint: disable=no-member
        requests_store = RequestJsonStore()
        requests_store.empty_store()
        keys_store = KeysJsonStore()
        keys_store.empty_store()

        # introduce a key valid and not expired and guest
        my_manager = AccessManager()
        my_manager.request_access_code("53935158C", "Marta Lopez",
                                       "Guest", "uc3m@gmail.com", 5)
        my_manager.request_access_code("34753293V", "Juan Perez",
                                       "Guest", "uc3m@gmail.com", 2)
        file_name = JSON_FILES_PATH + "key_ok.json"
        my_manager.get_access_key(file_name)

        file_name = JSON_FILES_PATH + "test_revoke_expired_access_key.json"
        my_manager.get_access_key(file_name)

    def test_st_rk_ckr_iv_1(self):
        test_file = JSON_FILES_PATH + "test_rev_no_exist.json"
        with self.assertRaises(AccessManagementException) as c_m:
            RevokeKey.create_key_from_file_for_revoke(test_file)
        self.assertEqual("key is not found or is expired", c_m.exception.message)

    def test_st_rk_ckr_v_2(self):
        test_file = JSON_FILES_PATH + "test_v_1.json"
        key = RevokeKey.create_key_from_file_for_revoke(test_file)
        result = isinstance(key, RevokeKey)
        self.assertEqual(result, True)

if __name__ == '__main__':
    unittest.main()
