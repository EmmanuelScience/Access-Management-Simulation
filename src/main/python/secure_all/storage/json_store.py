"""Generic class for JSON storage"""
import json
from secure_all.exception.access_management_exception import AccessManagementException


class JsonStore:
    """Manages stores based on JsonFiles"""
    _FILE_PATH = ""
    _ID_FIELD = ""
    _ENCODING = "utf-8"
    _NEWLINE = ""

    def __init__(self):
        self._data_list = []
        self.load_store()

    def empty_store(self):
        """empty the store"""
        self._data_list = []
        self.save_store()

    def load_store(self):
        """"Loads _data_list from the json file
        If the file is not found a new emtpy list is created """
        try:
            with open(self._FILE_PATH, "r", encoding=self._ENCODING, newline=self._NEWLINE) as file:
                self._data_list = json.load(file)
        except FileNotFoundError as ex:
            self._data_list = []
        except json.JSONDecodeError as ex:
            raise AccessManagementException("JSON Decode Error - Wrong JSON Format") from ex

    def add_item(self, item):
        """Adds a new element to the list and saves the file
        Since this is a generic class further verifications should be included
        in the specific stores"""
        self.load_store()
        self._data_list.append(item.store())
        self.save_store()

    def find_item(self, key):
        """find the value key in the _KEY_FIELD"""
        self.load_store()
        for item in self._data_list:
            if item[self._ID_FIELD] == key:
                return item
        return None

    def replace_item(self, key, new_item):
        """Removes the item from the JSON file found with the
        given key and adds the given new_item"""
        item = self.find_item(key)
        self._data_list.remove(item)
        self._data_list.append(new_item)
        self.save_store()

    def save_store(self):
        """Save the list in the json file _FILE_PATH
        Now it is not necessary check the list because it was created in the __init__
        so the only thing we need is to save the list in the file, raising and exception if
        the file doesn't exists """
        try:
            with open(self._FILE_PATH, "w", encoding=self._ENCODING, newline=self._NEWLINE) as file:
                json.dump(self._data_list, file, indent=2)
        except FileNotFoundError as ex:
            raise AccessManagementException("Wrong file or file path") from ex
