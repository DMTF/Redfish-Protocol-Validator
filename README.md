# Redfish Protocol Validator

Copyright 2020 DMTF. All rights reserved.

## About

The Redfish Protocol Validator tests the HTTP protocol behavior of a Redfish service to validate that it conforms to the Redfish specification.

## Installation

`git clone https://github.com/DMTF/Redfish-Protocol-Validator.git`

## Requirements

The Redfish Protocol Validator requires Python version 3 (v3.5 and later).

Required external packages:

```
aenum
colorama
pyasn1
pyasn1-modules
requests
sseclient-py
urllib3
```

You may install the external packages by running:

`pip install -r requirements.txt`

## Usage

```
usage: rf_protocol_validator.py [-h] [--version] --user USER --password
                                PASSWORD --rhost RHOST [--log-level LOG_LEVEL]
                                [--report-dir REPORT_DIR]
                                [--report-type {html,tsv,both}]
                                [--avoid-http-redirect]
                                [--no-cert-check | --ca-bundle CA_BUNDLE]

Validate the protocol conformance of a Redfish service

optional arguments:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  --user USER, -u USER  the username for authentication
  --password PASSWORD, -p PASSWORD
                        the password for authentication
  --rhost RHOST, -r RHOST
                        address of the Redfish service (with scheme)
  --log-level LOG_LEVEL
                        the logging level (default: WARNING)
  --report-dir REPORT_DIR
                        the directory for generated report files (default:
                        "reports")
  --report-type {html,tsv,both}
                        the type of report to generate: html, tsv, or both
                        (default: both)
  --avoid-http-redirect
                        avoid attempts to generate HTTP redirects for services
                        that do not support HTTP
  --no-cert-check       disable verification of host SSL certificates
  --ca-bundle CA_BUNDLE
                        the file or directory containing trusted CAs
```

Example: `python rf_protocol_validator.py -r https://192.168.1.100 -u USERNAME -p PASSWORD`

## Unit tests

The Redfish-Protocol-Validator unit tests are executed using the `tox` package.

You may install `tox` by running:

`pip install tox`

Running the unit tests:

`tox`
