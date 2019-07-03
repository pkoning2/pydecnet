#!/usr/bin/env python3

"""Installer for decnet module

Copyright (c) 2013-2019, Paul Koning.

Licensed under open source license terms stated in file LICENSE.
"""

from setuptools import setup

setup (author = "Paul Koning",
       author_email = "ni1d@arrl.net",
       license = "BSD",
       description = "DECnet protocol implementation in Python",
       name = "decnet",
       #url = ""
       version = "1.0",
       packages = [ "decnet", "decnet.applications", "decnet.resources" ],
       package_data = { "decnet.resources" : [ "*.txt", "*.css", "*.svg" ] },
       scripts = [ "pydecnet" ],
       py_modules = [ "crc" ],
       extras_require = {
           "daemon" : "python-daemon",
           "yaml" : "PyYAML",
           "pam" : "python-pam"
           },
       classifiers=[
           "Development Status :: 3 - Alpha",
           "Topic :: Communications",
           "License :: OSI Approved :: BSD License",
           "Programming Language :: Python :: 3.3",
           "Programming Language :: Python :: 3.4",
           "Programming Language :: Python :: 3.5",
           "Programming Language :: Python :: 3.6",
           "Programming Language :: Python :: 3.7",
           ],       
       )
