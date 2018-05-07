"""metadefender.manager: provides entry point main()."""

import sys
import os
import argparse
import hashlib
import json
from .metadefenderapi import MetaDefenderAPI

def getAPIKey():
    """
    Gets the API key from the config file
    """
    with open('metadefender/config.json') as fp:
        return json.load(fp)['apikey']

def setAPIKey(key):
    """
    Set the API key in the config file

    Arguments:
        key     -- The API key
    """
    with open('metadefender/config.json', 'w') as fp:
        json.dump({ 'apikey' : key }, fp)

def getHash(path, hashfunc='MD5'):
    """
    Gets the hash of a file.

    Arguments:
        path        -- The path of the file to hash
        hashfunc    -- The hashlib hash function to use
    """
    hasher = None
    if hashfunc == 'MD5':
        hasher = hashlib.md5()
    elif hashfunc == 'SHA1':
        hasher = hashlib.sha1()
    elif hashfunc == 'SHA256':
        hasher = hashlib.sha256()

    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(chunk)

    return hasher.hexdigest()

def scanFile(path, hasher='MD5', key=None):
    """
    Scans a file using metadefender API.

    Arguments:
        path    -- The path of the file to scan
        hasher  -- The hashlib hash function to use (default: MD5)
        key     -- The metadefender API key (default: [from config])
    """
    if key is not None:
        setAPIKey(key)

    md = MetaDefenderAPI(getAPIKey())
    
    # Calculate the hash of the file
    hashvalue = getHash(path, hasher)

    # do hash lookup, see if there are previously cached results
    result = md.getScanReportHash(hashvalue)

    if not 'scan_results' in result:
        # upload the file
        result = md.scanFile(path)
        dataid = result['data_id']

        # poll for scan results
        while True:
            result = md.getScanReportDataID(dataid)
            if 'scan_results' in result:
                break;
            #TODO add wait before we poll again

    md.displayScanResults(result)

def main():
    """
    The entry point for the metadefender tool.
    """
    # Set up argparser
    parser = argparse.ArgumentParser(
            description='simple metadefender client tool.')
    subparsers = parser.add_subparsers(
            dest='command', help='commands')

    # Set API key command
    api_key_parser = subparsers.add_parser(
            'setkey', help='Set the metadefender API key')
    api_key_parser.add_argument(
            'key', action='store', help='the metadefender API key')

    # Scan file command
    scan_parser = subparsers.add_parser(
            'scan', help='Scan a file using metadefender')
    scan_parser.add_argument(
            'path', action='store', help='The file to scan.')

    # Handle arguments
    arguments = parser.parse_args()
    if arguments.command == 'setkey':
        setAPIKey(arguments.key)
    elif arguments.command == 'scan':
        scanFile(arguments.path)
