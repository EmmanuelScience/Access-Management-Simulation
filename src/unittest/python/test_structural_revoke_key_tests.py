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
        my_manager.request_access_code("87654123L", "Maria Montero",
                                       "Guest", "maria@uc3m.es", 15)
        my_manager.request_access_code("53935158C", "Marta Lopez",
                                       "Guest", "uc3m@gmail.com", 5)
        my_manager.request_access_code("34753293V", "Juan Perez",
                                       "Guest", "uc3m@gmail.com", 2)
        file_name = JSON_FILES_PATH + "key_ok.json"
        my_manager.get_access_key(file_name)

        file_name = JSON_FILES_PATH + "key_ok2.json"
        my_manager.get_access_key(file_name)

        file_name = JSON_FILES_PATH + "test_revoke_expired_access_key.json"
        my_manager.get_access_key(file_name)

    def test_st_rk_rk_iv_1(self):
        test_file = JSON_FILES_PATH + "test_rev_expired.json"
        key = RevokeKey.create_key_from_file_for_revoke(test_file)
        with self.assertRaises(AccessManagementException) as c_m:
            key.revoke_key()
        self.assertEqual("Key already expired", c_m.exception.message)



    def test_st_rk_rk_v_2(self):
        test_file = JSON_FILES_PATH + "test_v_1.json"
        key = RevokeKey.create_key_from_file_for_revoke(test_file)
        result = key.revoke_key()
        self.assertEqual(result, 'mail1@uc3m.es, mail2@uc3m.es')


    def test_st_rk_rk_v_4(self):
        test_file = JSON_FILES_PATH + "test_st_rk_rk_v_4.json"
        key = RevokeKey.create_key_from_file_for_revoke(test_file)
        result = key.revoke_key()
        self.assertEqual(result, 'mail1@uc3m.es, mail2@uc3m.es')



if __name__ == '__main__':
    unittest.main()
