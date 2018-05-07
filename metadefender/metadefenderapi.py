"""metadefender.metadefenderapi: provides MetaDefenderAPI class definition."""

import sys
import requests

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
        """
        url = '{0}/v2/file'.format(MetaDefender.hostname)

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

        fp = open(path, "rb")
        payload = { 'file' : iter(lambda: fp.read(1024), b"") }
        r = requests.post(url, data=payload, headers=headers)
        fp.close()

        if not r.status_code == requests.codes.ok:
            sys.exit('Failed to upload file: {0}'.format(r.status_code))
            return None

        return r.json()

    def getScanReportDataID(self, dataid, file_metadata=None):
        """
        Retrieve scan status and results on a dataid.

        Arguments:
            dataid          -- The data ID recieved on upload.
            file_metadata   -- Retrieve file metadata and hash_results 
                               (default: None)
        """
        url = '{0}/v2/file/{1}'.format(MetaDefender.hostname, dataid)

        headers = { 'apikey' : setf._api_key }
        if file_metadata is not None:
            headers['file_metadata'] = file_metadata

        r = requests.get(url, headers=headers)

        if not r.status_code == requests.codes.ok:
            sys.exit('Failed to get scan report: {0}'.format(r.stats_code))
            return None

        return r.json()

    def getScanReportHash(self, hashvalue, file_metadata=None):
        """
        Retrieve scan results by hash.

        Arguments:
            hashvalue       -- The hash of a file (MD5, SHA1, SHA256)
            file_metadata   -- Add additional information in the response, 
                               like pe_info (default: None)
        """
        url = '{0}/v2/hash/{1}'.format(MetaDefender.hostname, hashvalue)

        headers = { 'apikey' : self._api_key }
        if file_metadata is not None:
            headers['file_metadata'] = file_metadata

        r = requests.get(url, headers=headers)

        if not r.status_code == requests.codes.ok:
            sys.exit('Failed to get scan report: {0}'.format(r.status_code))
            return None
        
        return r.json()

    def displayScanResults(self, scan):
        """
        Displays the results of the file scan.

        Arguments:
            scan    -- The JSON object containing the scan results
        """
        print('filename: {0}'.format(scan['file_info']['display_name']))
        print('overall_status: {0}'.format(scan['scan_results']['scan_all_result_a']))
        for key, value in scan['scan_results']['scan_details']:
            print()
            print('engine: {0}'.format(key))
            print('threat_found: {0}'.format(value['threat_found']))
            print('scan_result: {0}'.format(value['scan_result_i']))
            print('def_time: {0}'.format(value['def_time']))

