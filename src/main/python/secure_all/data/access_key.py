"""Contains the class Access Key"""
import hashlib
from datetime import datetime
from secure_all.exception.access_management_exception import AccessManagementException
from secure_all.data.access_request import AccessRequest
from secure_all.data.attributes.attribute_access_code import AccessCode
from secure_all.data.attributes.attribute_dni import Dni
from secure_all.data.attributes.attribute_email_list import EmailList
from secure_all.data.attributes.attribute_key import Key
from secure_all.storage.keys_json_store import KeysJsonStore
from secure_all.parser.key_json_parser import KeyJsonParser

CLOSE = "}"
OPEN = "{"
SEP = ","
EXPIRATION_DATE_KEY = "expirationdate:"
ISSUE_DATE_KEY = "issuedate:"
ACCESS_CODE_KEY = "accesscode:"
TYPE_KEY = "typ:"
ALG_KEY = "alg:"


class AccessKey:
    """Class representing the key for accessing the building"""
    # pylint: disable=too-many-instance-attributes
    ALG_SHA256 = "SHA-256"
    TYPE_DS = "DS"

    def __init__(self, dni, access_code, notification_emails, revoked=False):
        self.__alg = self.ALG_SHA256
        self.__type = self.TYPE_DS
        self.__access_code = AccessCode(access_code).value
        self.__dni = Dni(dni).value
        access_request = AccessRequest.create_request_from_code(self.__access_code)
        self.__notification_emails = EmailList(notification_emails).value
        validity = access_request.validity
        #just_now = datetime.utcnow()
        #self.__issued_at = datetime.timestamp(just_now)
        # fix self.__issued_at only for testing 13-3-2021 18_49
        self.__issued_at = 1615627129.580297
        if validity == 0:
            self.__expiration_date = 0
        else:
            # timestamp is represented in seconds.microseconds
            # validity must be expressed in seconds to be added to the timestamp
            self.__expiration_date = self.__issued_at + (validity * 30 * 24 * 60 * 60)
        self.__key = hashlib.sha256(self.__signature_string().encode()).hexdigest()
        self.__revoked = revoked
        self.__revocation = None
        self.__reason = None

    def store(self):
        """Returns a dictionary with all class attributes"""
        return self.__dict__

    def __signature_string(self):
        """Composes the string to be used for generating the key"""
        return (OPEN + ALG_KEY + self.__alg + SEP + TYPE_KEY + self.__type + SEP + ACCESS_CODE_KEY
                + self.__access_code + SEP + ISSUE_DATE_KEY + str(self.__issued_at) + SEP
                + EXPIRATION_DATE_KEY + str(self.__expiration_date) + CLOSE)

    def emails_to_str(self):
        """Returns a string with all the emails"""
        email_str = ""
        for email in self.__notification_emails:
            email_str += email + ", "
        return email_str[:-2]

    @property
    def expiration_date(self):
        """expiration_date getter"""
        return self.__expiration_date

    @expiration_date.setter
    def expiration_date(self, value):
        """expiration_date setter"""
        self.__expiration_date = value

    @property
    def dni(self):
        """Property that represents the dni of the visitor"""
        return self.dni

    @dni.setter
    def dni(self, value):
        """dni setter"""
        self.__dni = value

    @property
    def access_code(self):
        """Property that represents the access_code of the visitor"""
        return self.__access_code

    @access_code.setter
    def access_code(self, value):
        """access_code setter"""
        self.__access_code = value

    @property
    def notification_emails(self):
        """Property that represents the access_code of the visitor"""
        return self.__notification_emails

    @notification_emails.setter
    def notification_emails(self, value):
        """Setter for notification emails"""
        self.__notification_emails = value

    @property
    def key(self):
        """Property that represent the key"""
        return self.__key

    @key.setter
    def key(self, value):
        """Setter of the key value"""
        self.__key = value

    @property
    def revoked(self):
        """revoked getter"""
        return self.__revoked

    @revoked.setter
    def revoked(self, value):
        """revoked setter"""
        self.__revoked = value

    @property
    def revocation(self):
        """revocation getter"""
        return self.__revocation

    @revocation.setter
    def revocation(self, value):
        """revocation setter"""
        self.__revocation = value

    @property
    def reason(self):
        """reason getter"""
        return self.__reason

    @reason.setter
    def reason(self, value):
        """reason setter"""
        self.__reason = value

    def store_keys(self):
        """Storing the key in the keys store"""
        keys_store = KeysJsonStore()
        keys_store.add_item(self)

    def is_valid(self):
        """Return true if the key is not expired"""
        just_now = datetime.utcnow()
        just_now_timestamp = datetime.timestamp(just_now)
        if not (self.__expiration_date == 0 or
                self.__expiration_date > just_now_timestamp):
            raise AccessManagementException("key is not found or is expired")
        if self.get_revoked(self.__key):
            raise AccessManagementException("key already revoked")
        return True

    @classmethod
    def create_key_from_file(cls, key_file):
        """Class method from creating an instance of AccessKey
        from the content of a file according to RF2"""
        access_key_items = KeyJsonParser(key_file).json_content
        return cls(access_key_items[KeyJsonParser.DNI],
                   access_key_items[KeyJsonParser.ACCESS_CODE],
                   access_key_items[KeyJsonParser.MAIL_LIST])

    @classmethod
    def create_key_from_id(cls, key):
        """Class method from creating an instance of AccessKey
        retrieving the information from the keys store"""
        keys_store = KeysJsonStore()
        key_object = keys_store.find_item(Key(key).value)
        if key_object is None:
            raise AccessManagementException("key is not found or is expired")
        return cls(key_object[keys_store.DNI],
                   key_object[keys_store.ACCESS_CODE],
                   key_object[keys_store.MAIL_LIST])

    @classmethod
    def get_revoked(cls, key):
        """Class method from creating an instance of AccessKey
        retrieving the information from the keys store"""
        keys_store = KeysJsonStore()
        key_object = keys_store.find_item(Key(key).value)
        if key_object is None:
            raise AccessManagementException("key is not found or is expired")
        return bool(key_object["_AccessKey__revoked"])
