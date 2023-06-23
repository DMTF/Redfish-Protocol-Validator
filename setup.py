# Copyright Notice:
# Copyright 2020-2022 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/Redfish-Protocol-Validator/blob/main/LICENSE.md

from setuptools import setup
from codecs import open

with open("README.md", "r", "utf-8") as f:
    long_description = f.read()

setup(
    name="redfish_protocol_validator",
    version="1.1.8",
    description="Redfish Protocol Validator",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="DMTF, https://www.dmtf.org/standards/feedback",
    license="BSD 3-clause \"New\" or \"Revised License\"",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "License :: OSI Approved :: BSD License",
        "Programming Language :: Python",
        "Topic :: Communications"
    ],
    keywords="Redfish",
    url="https://github.com/DMTF/Redfish-Protocol-Validator",
    packages=["redfish_protocol_validator"],
    entry_points={
        'console_scripts': ['rf_protocol_validator=redfish_protocol_validator.console_scripts:main']
    },
    install_requires=["aenum", "colorama", "pyasn1", "pyasn1-modules",
                      "requests>=2.23.0", "sseclient-py", "urllib3<2"]
)
