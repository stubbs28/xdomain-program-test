"""metadefender.metadefenderapi: provides MetaDefenderAPI class definition."""

import sys
import requests
import json

class MetaDefenderAPI:
    """A class for accessing the metadefender REST API"""
    hostname = 'https://api.metadefender.com'

    def __init__(self, key):
        """
        Initializes the API.
        """
        self._api_key = key

    def scanFile(self, path, filename=None, archivepwd=None, samplesharing=None, 
            downloadfrom=None, user_agent=None):
        """
        Uploads a file to metadefender to be scanned.

        Arguments:
            path            -- The path of the file to upload
            filename        -- The name of files to preserve extension and 
                                metadata during scan (default: None)
            archivepwd      -- If submitted file is password-protected archive 
                                (default: None)
            samplesharing   -- Only working for paid users - allow file scans 
                                to be shared or not (default: None)
            downloadfrom    -- link to download file, allow user to scan file 
                                by link before actually downloading it 
                                (default: None)
            user_agent      -- activate workflows (default: None)

        Returns:
            The JSON response from the server.
        """
        url = '{0}/v2/file'.format(MetaDefenderAPI.hostname)

        headers = { 'apikey' : self._api_key }
        if filename is not None:
            headers['filename'] = filename
        if archivepwd is not None:
            headers['archivepwd'] = archivepwd
        if samplesharing is not None:
            headers['samplesharing'] = samplesharing
        if downloadfrom is not None:
            headers['downloadfrom'] = downloadfrom
        if user_agent is not None:
            headers['user_agent'] = user_agent

        files = { 'file' : open(path, 'rb') }
        r = requests.post(url, files=files, headers=headers)

        if not r.status_code == requests.codes.ok:
            sys.exit('Failed to upload file: {0}'.format(r.status_code))

        return r.json()

    def getScanReportDataID(self, dataid, file_metadata=None):
        """
        Retrieve scan status and results on a dataid.

        Arguments:
            dataid          -- The data ID recieved on upload.
            file_metadata   -- Retrieve file metadata and hash_results 
                                (default: None)

        Returns:
            The JSON response from the server.
        """
        url = '{0}/v2/file/{1}'.format(MetaDefenderAPI.hostname, dataid)

        headers = { 'apikey' : self._api_key }
        if file_metadata is not None:
            headers['file_metadata'] = file_metadata

        r = requests.get(url, headers=headers)

        if not r.status_code == requests.codes.ok:
            sys.exit('Failed to get scan report: {0}'.format(r.stats_code))

        return r.json()

    def getScanReportHash(self, hashvalue, file_metadata=None):
        """
        Retrieve scan results by hash.

        Arguments:
            hashvalue       -- The hash of a file (MD5, SHA1, SHA256)
            file_metadata   -- Add additional information in the response, like 
                                pe_info (default: None)

        Returns:
            The JSON response from the server.
        """
        url = '{0}/v2/hash/{1}'.format(MetaDefenderAPI.hostname, hashvalue)

        headers = { 'apikey' : self._api_key }
        if file_metadata is not None:
            headers['file_metadata'] = file_metadata

        r = requests.get(url, headers=headers)

        if not r.status_code == requests.codes.ok:
            sys.exit('Failed to get scan report: {0}'.format(r.status_code))
        
        return r.json()

    def displayScanResults(self, scan):
        """
        Displays the results of the file scan.

        Arguments:
            scan    -- The JSON object containing the scan results
        """
        if 'file_info' in scan and 'display_name' in scan['file_info']:
            print('filename: {0}'.format(scan['file_info']['display_name']))
        if 'scan_results' in scan:
            scan_results = scan['scan_results']
            if 'scan_all_result_a' in scan_results:
                print('overall_status: {0}'.format(scan_results['scan_all_result_a']))
            if 'scan_details' in scan_results:
                print ('scan_details:')
                for key in scan_results['scan_details'].keys():
                    result = scan_results['scan_details'][key]
                    print()
                    print('engine: {0}'.format(key))
                    threat_found = result['threat_found']
                    if threat_found == '':
                        threat_found = 'Clean'
                    print('threat_found: {0}'.format(threat_found))
                    print('scan_result: {0}'.format(result['scan_result_i']))
                    print('def_time: {0}'.format(result['def_time']))
