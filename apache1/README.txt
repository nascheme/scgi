Building
--------

Using the 'apxs' tool:

    $ apxs -i -c mod_scgi.c

Alternatively, you can use 'make' and 'make install'.


Configuration
-------------

To enable, add

    LoadModule scgi_module /<some path>/mod_scgi.so

in your httpd.conf file.  Note that it is best to load mod_scgi after
mod_rewrite (mod_rewrite needs a higher priority in order to rewrite
URLs served by mod_scgi).  To serve a set of URLs under one path with
an SCGI server, use the SCGIMount directive:

    SCGIMount /dynamic 127.0.0.1:4000


Demo
-----

Quixote >= 2.0a2 has a demo application you can try out by running:

  python $QUIXOTE/server/scgi_server.py --port 4000

with the appropriate path for $QUIXOTE.  If you have Quixote 1.3 or
2.0a1 installed, use the driver bundled with SCGI instead:

  python scgi/quixote_handler.py -F

If you don't have Quixote, the SCGI server doubles as a standalone
demo:

  python scgi/scgi_server.py 4000

