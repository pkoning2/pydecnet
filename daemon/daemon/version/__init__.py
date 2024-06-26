# -*- coding: utf-8 -*-

# daemon/version/__init__.py
# Part of python-daemon, an implementation of PEP 3143.
#
# Copyright © 2008–2010 Ben Finney <ben+python@benfinney.id.au>
# This is free software: you may copy, modify, and/or distribute this work
# under the terms of the Python Software Foundation License, version 2 or
# later as published by the Python Software Foundation.
# No warranty expressed or implied. See the file LICENSE.PSF-2 for details.

""" Version information for the python-daemon distribution. """

from daemon.version.version_info import version_info

version_info['version_string'] = "1.5.5"

version_short = "%(version_string)s" % version_info
version_full = "%(version_string)s.r%(revno)s" % version_info
version = version_short

author_name = "Ben Finney"
author_email = "ben+python@benfinney.id.au"
author = "%(author_name)s <%(author_email)s>" % vars()

copyright_year_begin = "2001"
date = version_info['date'].split(' ', 1)[0]
copyright_year = date.split('-')[0]
copyright_year_range = copyright_year_begin
if copyright_year > copyright_year_begin:
    copyright_year_range += "–%(copyright_year)s" % vars()

copyright = (
    "Copyright © %(copyright_year_range)s %(author)s and others"
    ) % vars()
license = "PSF-2+"
