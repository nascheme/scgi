#!/usr/bin/env python

import sys
from distutils.core import setup
from distutils.extension import Extension
from scgi.__init__ import __version__

# Ensure that version number is correct.
def _check_version_numbers():
    import re
    PAT = re.compile(r'(^|VERSION ")%s\b' % re.escape(__version__), re.M)
    for fn in ["CHANGES.txt", "apache1/mod_scgi.c", "apache2/mod_scgi.c"]:
        if not PAT.search(open(fn).read(200)):
            raise AssertionError("version number mismatch in %r" % fn)

if 'sdist' in sys.argv[1:]:
    _check_version_numbers()

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
