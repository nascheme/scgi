#!/usr/bin/env python

import sys
import re
from distutils.core import setup
from distutils.extension import Extension
from scgi.__init__ import __version__

# Ensure that version number is correct.
PAT = re.compile(r'^%s\b' % re.escape(__version__), re.MULTILINE)
if not PAT.search(open("CHANGES.txt").read(400)):
    raise AssertionError("version number mismatch in CHANGES.txt")

setup(name = "scgi",
      version = __version__,
      description = "A Python package for implementing SCGI servers.",
      author = "Neil Schemenauer",
      author_email = "nas@mems-exchange.org",
      url = "http://www.mems-exchange.org/software/scgi/",
      license = "see LICENSE.txt",
      packages = ['scgi'],
      ext_modules = [Extension(name="scgi.passfd", sources=['scgi/passfd.c'])],
      )
