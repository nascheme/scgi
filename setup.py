#!/usr/bin/env python3

import sys
from distutils import core
from distutils.extension import Extension
from scgi.__init__ import __version__

# Ensure that version number is correct.
def _check_version_numbers():
    import re
    PAT = re.compile(r'(^|VERSION ")%s\b' % re.escape(__version__), re.M)
    for fn in ["apache1/mod_scgi.c", "apache2/mod_scgi.c"]:
        if not PAT.search(open(fn).read(200)):
            raise AssertionError("version number mismatch in %r" % fn)

if 'sdist' in sys.argv[1:]:
    _check_version_numbers()

kw = dict(
    name = "scgi",
    version =  __version__,
    description =  "A Python package for implementing SCGI servers.",
    author =  "Neil Schemenauer",
    author_email =  "nas@arctrix.com",
    #url =  "http://",
    license =  "DFSG approved (see LICENSE.txt)",
    packages =  ['scgi'],
    ext_modules =  [Extension(name="scgi.passfd", sources=['scgi/passfd.c'])],
    )

# If we're running Python 2.3, add extra information
if hasattr(core, 'setup_keywords'):
    if 'classifiers' in core.setup_keywords:
        kw['classifiers'] = ['Development Status :: 5 - Production/Stable',
          'Environment :: Web Environment',
          'License :: DFSG approved',
          'Intended Audience :: Developers',
          'Operating System :: Unix',
          'Operating System :: Microsoft :: Windows',
          'Operating System :: MacOS :: MacOS X',
          'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
          ]
    if 'download_url' in core.setup_keywords:
        kw['download_url'] = ('http://python.ca/scgi/releases/'
                              'scgi-%s.tar.gz' % kw['version'])
    if 'url' in core.setup_keywords:
        kw['url'] = 'http://python.ca/scgi/'


core.setup(**kw)
