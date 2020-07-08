# Copyright Notice:
# Copyright 2020 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#     https://github.com/DMTF/Redfish-Protocol-Validator/blob/master/LICENSE.md

from setuptools import setup

setup(
    name="redfish_protocol_validator",
    version="0.9.0",
    description="Redfish Protocol Validator",
    author="DMTF, https://www.dmtf.org/standards/feedback",
    license="BSD 3-clause \"New\" or \"Revised License\"",
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: BSD License",
        "Programming Language :: Python",
        "Topic :: Communications"
    ],
    keywords="Redfish",
    url="https://github.com/DMTF/Redfish-Protocol-Validator",
    packages=["assertions"],
    install_requires=["aenum", "colorama", "pyasn1", "pyasn1-modules",
                      "requests", "sseclient-py", "urllib3"]
)
