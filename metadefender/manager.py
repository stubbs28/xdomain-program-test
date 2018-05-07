"""metadefender.manager: provides entry point main()."""

import sys
import argparse
import hashlib
import json
from .metadefenderapi import MetaDefenderAPI

def getAPIKey():
    """
    Gets the API key from the config file
    """
    try:
        with open('metadefender/config.json') as fp:
            return json.load(fp)['apikey']
    except:
        sys.exit('API key not set.')

def setAPIKey(key):
    """
    Set the API key in the config file

    Arguments:
        key     -- The API key
    """
    with open('metadefender/config.json', 'w') as fp:
        json.dump({ 'apikey' : key }, fp)

def getHash(path, hashfunc):
    """
    Gets the hash of a file.

    Arguments:
        path        -- The path of the file to hash
        hashfunc    -- The hashlib hash function to use

    Returns:
        The hash of the given file.
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

def scanFile(path, verbose=False, showresp=False, rescan=False, hasher=None, key=None):
    """
    Scans a file using metadefender API.

    Arguments:
        path            -- The path of the file to scan
        hasher          -- The hashlib hash function to use (default: None)
        key             -- The metadefender API key (default: None)
        verbose         -- Runs the scanner with more verbosity (default: False)
        showresponse    -- Prints the responses from the server (default: False)
    """
    if key is None:
        key = getAPIKey()

    md = MetaDefenderAPI(key)
    result = {}
    
    if not rescan:
        # Calculate the hash of the file
        if hasher is None:
            hasher = 'MD5'
        hashvalue = getHash(path, hasher)

        if verbose:
            print('{0} hash of {1}: {2}\n'.format(hasher, path, hashvalue))
            print('Looking up scan results...\n')

        # do hash lookup, see if there are previously cached results
        result = md.getScanReportHash(hashvalue)

        if showresp:
            print(json.dumps(result, indent=2))

    if not 'scan_results' in result:
        if verbose:
            if not rescan:
                print('No scan results found.\n')
            print('Uploading file for scan...\n')

        # upload the file
        result = md.scanFile(path)

        if showresp:
            print(json.dumps(result, indent=2))

        dataid = result['data_id']

        if verbose:
            print('File uploaded. Data ID: {0}\n'.format(dataid))

        # poll for scan results
        if verbose:
            print('Polling for scan results...\n')

        while True:
            result = md.getScanReportDataID(dataid)

            if showresp:
                print(json.dumps(result, indent=2))

            if 'scan_results' in result:
                progress = result['scan_results']['progress_percentage']
                sys.stdout.write('\rScan Progress: {0}'.format(progress))
                if progress == 100:
                    print('\n')
                    break;

    print('Scan Results:')
    md.displayScanResults(result)

def main():
    """
    The entry point for the metadefender tool.
    """
    # Set up argparser
    parser = argparse.ArgumentParser(
            description='Simple metadefender client tool.')
    subparsers = parser.add_subparsers(
            dest='command', help='Commands')

    # Set API key command
    api_key_parser = subparsers.add_parser(
            'setkey', help='Set the metadefender API key')
    api_key_parser.add_argument(
            'key', help='The metadefender API key')

    # Scan file command
    scan_parser = subparsers.add_parser(
            'scan', help='Scan a file using metadefender')
    scan_parser.add_argument(
            '-v', '--verbose', action='store_true', dest='verbose',
            help='Turns on verbosity')
    scan_parser.add_argument(
            '-s', '--showresponse', action='store_true', dest='showresp',
            help='Show the json responses from the server.')
    scan_parser.add_argument(
            '-r', '--rescan', action='store_true', dest='rescan',
            help='Rescan the file.')
    group = scan_parser.add_mutually_exclusive_group()
    group.add_argument('--md5', action='store_const', const='MD5',
            dest='hasher', help='Use MD5 to hash the file')
    group.add_argument('--sha1', action='store_const', const='SHA1',
            dest='hasher', help='Use SHA1 to hash the file')
    group.add_argument('--sah256', action='store_const', const='SHA256',
            dest='hasher', help='Use SHA256 to hash the file')
    scan_parser.add_argument(
            '-k', '--key', dest='key', 
            help='Set the metadefender API key')
    scan_parser.add_argument(
            'path', action='store', help='The file to scan.')

    # Handle arguments
    arguments = parser.parse_args()
    if arguments.command == 'setkey':
        setAPIKey(arguments.key)
    elif arguments.command == 'scan':
        scanFile(path=arguments.path,
                verbose=arguments.verbose,
                showresp=arguments.showresp,
                rescan=arguments.rescan,
                hasher=arguments.hasher,
                key=arguments.key)
