#!/usr/bin/env python3

"""Installer for decnet module

Copyright (c) 2013-2020, Paul Koning.

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
       python_requires = ">=3.3",
       packages = [ "decnet", "decnet.modules",
                    "decnet.applications", "decnet.resources",
                    "decnet.resources.images" ],
       package_data = { "decnet.resources" : [ "*.txt", "*.css", "*.svg", "*.js" ],
                        "decnet.resources.images" : [ "*.png" ]},
       entry_points  = {
           "console_scripts" : [
               "pydecnet = decnet.main:main"
            ]
        },
       py_modules = [ "crc" ],
       install_requires = [
           "psutil >= 3.2.0"
           ],
       extras_require = {
           "daemon" : "python-daemon",
           "yaml" : "PyYAML",
           "pam" : "python-pam",
           "serial" : "pyserial",
           "uart" : "Adafruit_BBIO"
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
           "Programming Language :: Python :: 3.8",
           "Programming Language :: Python :: 3.9",
           "Programming Language :: Python :: 3.10",
           ],       
       )
