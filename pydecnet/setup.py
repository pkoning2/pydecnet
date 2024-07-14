#!/usr/bin/env python3

"""Installer for decnet module

Copyright (c) 2013-2024, Paul Koning.

Licensed under open source license terms stated in file LICENSE.
"""

from setuptools import setup
from decnet.version import DNKITVERSION, DNREV
import os.path

if DNREV:
    with open (os.path.join (os.path.dirname (__file__), "decnet", "GITREV"), "wt") as f:
        print (DNREV, file = f)
        
setup (author = "Paul Koning",
       author_email = "ni1d@arrl.net",
       license = "BSD",
       description = "DECnet protocol implementation in Python",
       name = "decnet",
       url = "http://akdesign.dyndns.org:8080/resources/public/index.html",
       version = DNKITVERSION,
       python_requires = ">=3.7",
       packages = [ "decnet", "decnet.modules",
                    "decnet.applications", "decnet.resources",
                    "decnet.resources.images", "applications" ],
       package_data = { "decnet.resources" : [ "*.txt", "*.css", "*.js", "*.html" ],
                        "decnet.resources.images" : [ "*.png", "*.svg" ],
                        "applications" : [ "*" ]},
       # read MANIFEST.in and include files mentioned here to the package
       include_package_data = True,
       # this package will read some included files in runtime, avoid
       # installing it as .zip
       zip_safe = False,
       entry_points  = {
           "console_scripts" : [
               "pydecnet = decnet.main:main"
            ]
        },
       py_modules = [ "crc" ],
       scripts = [ "applications/ncp", "applications/mirror-daemon",
                   "applications/nft", "applications/tlk",
                   "applications/dnping", "applications/rcclient" ],
       extras_require = {
           "daemon" : "python-daemon",
           "yaml" : "PyYAML",
           "pam" : "python-pam",
           "serial" : "pyserial",
           "uart" : "Adafruit_BBIO"
           },
       classifiers=[
           "Development Status :: 5 - Production/Stable",
           "Topic :: Communications",
           "Environment :: Console",
           "License :: OSI Approved :: BSD License",
           "Operating System :: POSIX",
           "Programming Language :: Python :: 3.7",
           "Programming Language :: Python :: 3.8",
           "Programming Language :: Python :: 3.9",
           "Programming Language :: Python :: 3.10",
           "Programming Language :: Python :: 3.11",
           "Programming Language :: Python :: 3.12",
           "Programming Language :: Python :: 3.13",
           ],
       )
