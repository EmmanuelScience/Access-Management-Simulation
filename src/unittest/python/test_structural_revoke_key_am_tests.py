import unittest
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
        file_name = JSON_FILES_PATH + "key_ok.json"
        my_manager.get_access_key(file_name)

    def test_st_am_rk_v_1(self):
        my_test = AccessManager()
        file = JSON_FILES_PATH + "test_v_1.json"
        result = my_test.revoke_key(file)
        self.assertEqual(result, 'mail1@uc3m.es, mail2@uc3m.es')

if __name__ == '__main__':
    unittest.main()
