"""parser for input key revocation files"""
from secure_all.parser.json_parser import JsonParser


class RevokeJsonParser(JsonParser):
    """parser for input key files containing a AccessKey request"""
    #pylint: disable=too-few-public-methods
    KEY = "Key"
    REVOCATION = "Revocation"
    REASON = "Reason"
    _key_list = [KEY, REVOCATION, REASON]
    _key_error_message = "JSON Decode Error - Wrong JSON Format"
