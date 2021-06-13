#!/usr/bin/env python3

import sys
import re
import os
from setuptools import setup, Extension
from scgi.__init__ import __version__

# Ensure that version number is correct.
def _check_version_numbers():
    PAT = re.compile(r'(^|VERSION ")%s\b' % re.escape(__version__), re.M)
    for fn in ["apache2/mod_scgi.c"]:
        if not PAT.search(open(fn).read(200)):
            raise AssertionError("version number mismatch in %r" % fn)


if 'sdist' in sys.argv[1:]:
    _check_version_numbers()


setup(
    name="scgi",
    version=__version__,
    description="A Python package for implementing SCGI servers.",
    author="Neil Schemenauer",
    author_email="nas@arctrix.com",
    # url =  "http://",
    license="DFSG approved (see LICENSE.txt)",
    packages=['scgi'],
    ext_modules=[Extension(name="scgi.passfd", sources=['scgi/passfd.c'])],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Web Environment',
        'License :: DFSG approved',
        'Intended Audience :: Developers',
        'Operating System :: Unix',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: MacOS :: MacOS X',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Programming Language :: Python :: 3 :: Only',
    ],
    download_url=(
        'http://python.ca/scgi/releases/' 'scgi-%s.tar.gz' % __version__
    ),
    url='http://python.ca/scgi/',
    python_requires='>=3.5',
)
