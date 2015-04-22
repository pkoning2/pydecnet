#!/usr/bin/env python

"""Installer for decnet module

Copyright (c) 2013-2015 G. Paul Koning.

Licensed under open source license terms stated in file LICENSE.
"""

from distutils.core import setup

#Copyright = __doc__.split ('\n')[2]
Version = "1.0"
License = '\n'.join (__doc__.split ('\n')[2:])
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
       )
