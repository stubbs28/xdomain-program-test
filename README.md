# Xdomain Program Test
> Scans a file against OPSWAT metadefender.

This is a simple program for scanning a file against the [OPSWAT MetaDefender Cloud](metadefender.opswat.com).

## Setup

This project uses [python 3](https://www.python.org/downloads).

You will also need to install the [Requests](http://docs.python-requests.org/en/master/user/install/#install) module:
```sh
pip install requests
```

## Usage example

Navigate to the top level of the project directory and run:
```sh
python3 run.py scan -k apikey fileToScan.txt
```
If the file has not been scanned, it will be uploaded to metadefender for a scan.
Scan results for the file will then be displayed.

If you would like to perminatly set the API key for future use, you can run:
```sh
python3 run.py setkey apikey
```

For additional help run:
```
python3 run.py -h
```

## Meta

Lexi Stubbs - stubbs28@gmail.com
