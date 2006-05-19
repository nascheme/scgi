#!/usr/bin/env python

from distutils.core import setup
from distutils.extension import Extension

setup(name = "scgi",
      version = "1.10",
      description = "A Python package for implementing SCGI servers.",
      author = "Neil Schemenauer",
      author_email = "nas@mems-exchange.org",
      url = "http://www.mems-exchange.org/software/scgi/",
      license = "see LICENSE.txt",
      packages = ['scgi'],
      ext_modules = [Extension(name="scgi.passfd", sources=['scgi/passfd.c'])],
      )
