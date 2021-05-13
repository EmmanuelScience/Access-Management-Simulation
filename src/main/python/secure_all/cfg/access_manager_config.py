"""Global constants for finding the path"""
import os

FILE_DIR = os.path.realpath(__file__)
mfi = FILE_DIR.index("G88.T04.FP")
mfi += len("G88.T04.FP")
PROJECT_DIR = FILE_DIR[:mfi]
SEP = os.path.sep
JSON_FILES_PATH = PROJECT_DIR + SEP + 'src' + SEP + 'JsonFiles' + SEP
