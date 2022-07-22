# Redfish Protocol Validator

Copyright 2020-2022 DMTF. All rights reserved.

## About

The Redfish Protocol Validator tests the HTTP protocol behavior of a Redfish service to validate that it conforms to the Redfish Specification.

## Installation

From PyPI:

    pip install redfish_protocol_validator

From GitHub:

    git clone https://github.com/DMTF/Redfish-Protocol-Validator.git
    cd Redfish-Protocol-Validator
    python setup.py sdist
    pip install dist/redfish_protocol_validator-x.x.x.tar.gz

## Requirements

The Redfish Protocol Validator requires Python version 3 (v3.5 and later).

Required external packages:

```
aenum
colorama
pyasn1
pyasn1-modules
requests>=2.23.0
sseclient-py
urllib3
```

If installing from GitHub, you may install the external packages by running:

    pip install -r requirements.txt

## Usage

```
usage: rf_protocol_validator.py [-h] [--version] --user USER --password
                                PASSWORD --rhost RHOST [--log-level LOG_LEVEL]
                                [--report-dir REPORT_DIR]
                                [--report-type {html,tsv,both}]
                                [--avoid-http-redirect]
                                [--no-cert-check | --ca-bundle CA_BUNDLE]

Validate the protocol conformance of a Redfish service

required arguments:
  --user USER, -u USER  the username for authentication
  --password PASSWORD, -p PASSWORD
                        the password for authentication
  --rhost RHOST, -r RHOST
                        address of the Redfish service (with scheme)

optional arguments:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  --log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}
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

Example:

    rf_protocol_validator -r https://192.168.1.100 -u USERNAME -p PASSWORD

## Unit Tests

The Redfish Protocol Validator unit tests are executed using the `tox` package.

You may install `tox` by running:

    pip install tox

Running the unit tests:

    tox

## Release Process

1. Go to the "Actions" page
2. Select the "Release and Publish" workflow
3. Click "Run workflow"
4. Fill out the form
5. Click "Run workflow"
