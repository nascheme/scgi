SCGI: A Simple Common Gateway Interface alternative
===================================================

Protocol
--------

    SCGI is a protocol for connecting web application servers to HTTP
    servers (e.g. Apache).  For typical applications, it provides much
    better performance verses using CGI.  See http://python.ca/scgi/ for
    details on the SCGI protocol including a specification.


Software
--------

    See doc/guide.html for an overview of how SCGI works.  Below is a
    list of components included in this package.

    scgi
    ----

        A Python package implementing the server side of the SCGI
        protocol.


    apache1
    -------

        An Apache 1.3 module that implements the client side of the
        protocol.  See the README file in the apache1 directory for more
        details.


    apache2
    -------

        An Apache 2.0 module that implements the client side of the
        protocol.  See the README file in the apache2 directory for more
        details.


    cgi2scgi
    --------

        A CGI script that forwards requests to a SCGI server.  This is
        useful in situations where you cannot or do not want to use the
        mod_scgi module.  Because the CGI script is small performance is
        quite good.

        To use, edit the source and specify the correct address and port
        of the SCGI server.  Next, compile using a C compiler, e.g.:

            $ cc -o myapp.cgi cgi2scgi.c

       Finally, put the script in the proper directory (depends on web
       server software used).


Source
------

    The source code is managed using git.  You can checkout a copy using
    the command:

        git clone http://quixote.ca/src/scgi.git


License
-------

    The SCGI package is copyrighted and made available under open source
    licensing terms.  See the LICENSE.txt file for the details.  The
    CHANGES.txt file summarizes recent changes made to the package.


/* vim: set ai tw=74 et sw=4 sts=4: */
