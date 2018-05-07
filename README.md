# Xdomain Program Test
> Scans a file against OPSWAT metadefender.

This is a simple program for scanning a file against the metadefender.opswat.com API.

## Setup

This project uses [python 3](https://www.python.org/downloads).

You will also need the following modules installed:
1. Requests
```sh
pip install requests
```

## Usage example

1. Navigate to the top level of the project directory
2. Set the API key:
```sh
python3 run.py setkey secret
```
3. Scan a file:
```sh
python3 run.py scan fileToScan.txt
```

For additional help run:
```
python3 run.py -h
```

## Meta

Lexi Stubbs - stubbs28@gmail.com
