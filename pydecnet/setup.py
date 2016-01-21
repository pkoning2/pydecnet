#!/usr/bin/env python3

"""Installer for decnet module

Copyright (c) 2013-2016, Paul Koning.

Licensed under open source license terms stated in file LICENSE.
"""

import sys
if sys.version_info[0] < 3 or sys.version_info[1] < 3:
    print ("PyDECnet requires Python 3.3 or later")
    sys.exit (1)

from setuptools import setup

Version = "1.0"
License = "BSD"
FullName = "DECnet protocol implementation in Python"
Name = "decnet"

setup (author = "Paul Koning",
       author_email = "ni1d@arrl.net",
       license = License,
       description = FullName,
       name = Name,
       #url = ""
       version = Version,
       packages = [ "decnet" ],
       scripts = [ "pydecnet" ],
       py_modules = [ "crc" ],
       install_requires = [ "python-daemon-3K" ],
       classifiers=[
           "Development Status :: 3 - Alpha",
           "Topic :: Communications",
           "License :: OSI Approved :: BSD License",
           "Programming Language :: Python :: 3.3",
           "Programming Language :: Python :: 3.4",
           "Programming Language :: Python :: 3.5",
           ],       
       )
