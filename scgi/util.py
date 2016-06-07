import sys
import os
import time
import codecs
import socket
from scgi import passfd


def log(msg):
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    sys.stderr.write('[%s] %s\n' % (timestamp, msg))


# netstring utility functions
def ns_read_size(input):
    size = b''
    while 1:
        c = input.read(1)
        if c == b':':
            break
        elif not c:
            raise IOError('short netstring read')
        size = size + c
    return int(size)


def ns_reads(input):
    size = ns_read_size(input)
    data = b''
    while size > 0:
        s = input.read(size)
        if not s:
            raise IOError('short netstring read')
        data = data + s
        size -= len(s)
    if input.read(1) != b',':
        raise IOError('missing netstring terminator')
    return data


# string encoding for evironmental variables
HEADER_ENCODING = 'iso-8859-1'


def parse_env(headers):
    items = headers.split(b'\0')
    items = items[:-1]
    if len(items) % 2 != 0:
        raise ValueError('malformed headers')
    env = {}
    for i in range(0, len(items), 2):
        k = items[i].decode(HEADER_ENCODING)
        v = items[i+1].decode(HEADER_ENCODING)
        env[k] = v
    return env


def read_env(input):
    headers = ns_reads(input)
    return parse_env(headers)


class SCGIHandler:

    # Subclasses should normally override the produce method.

    def __init__(self, parent_fd):
        self.parent_fd = parent_fd

    def serve(self):
        while 1:
            try:
                os.write(self.parent_fd, b'1') # indicates that child is ready
                fd = passfd.recvfd(self.parent_fd)
            except (IOError, OSError):
                # parent probably exited (EPIPE comes thru as OSError)
                raise SystemExit
            conn = socket.fromfd(fd, socket.AF_INET, socket.SOCK_STREAM)
            # Make sure the socket is blocking.  Apparently, on FreeBSD the
            # socket is non-blocking.  I think that's an OS bug but I don't
            # have the resources to track it down.
            conn.setblocking(1)
            os.close(fd)
            try:
                self.handle_connection(conn)
            finally:
                try:
                    conn.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                conn.close()

    def read_env(self, input):
        return read_env(input)

    def handle_connection(self, conn):
        """Handle an incoming request. This used to be the function to
        override in your own handler class, and doing so will still work.
        It will be easier (and therefore probably safer) to override
        produce() or produce_cgilike() instead.
        """
        input = conn.makefile("rb")
        output = conn.makefile("wb")
        env = self.read_env(input)
        bodysize = int(env.get('CONTENT_LENGTH', 0))
        try:
            self.produce(env, bodysize, input, output)
        finally:
            output.close()
            input.close()

    def produce(self, env, bodysize, input, output):
        """This is the function you normally override to run your
        application. It is called once for every incoming request that
        this process is expected to handle.

        Parameters:

        env - a dict mapping CGI parameter names to their values.

        bodysize - an integer giving the length of the request body, in
        bytes (or zero if there is none).

        input - a file allowing you to read the request body, if any,
        over a socket. The body is exactly bodysize bytes long; don't
        try to read more than bodysize bytes. This parameter is taken
        from the CONTENT_LENGTH CGI parameter.

        output - a file allowing you to write your page over a socket
        back to the client.  Before writing the page's contents, you
        must write an http header, e.g. "Content-Type: text/plain\\r\\n"

        The default implementation of this function sets up a CGI-like
        environment, calls produce_cgilike(), and then restores the
        original environment for the next request.  It is probably
        faster and cleaner to override produce(), but produce_cgilike()
        may be more convenient.
        """

        # Preserve current system environment
        stdin = sys.stdin
        stdout = sys.stdout
        environ = os.environ

        # Set up CGI-like environment for produce_cgilike()
        sys.stdin = codecs.getreader('utf-8')(input)
        sys.stdout = codecs.getwriter('utf-8')(output)
        os.environ = env

        # Call CGI-like version of produce() function
        try:
            self.produce_cgilike(env, bodysize)
        finally:
            # Restore original environment no matter what happens
            sys.stdin.close()
            sys.stdout.close()
            sys.stdin = stdin
            sys.stdout = stdout
            os.environ = environ


    def produce_cgilike(self, env, bodysize):
        """A CGI-like version of produce. Override this function instead
        of produce() if you want a CGI-like environment: CGI parameters
        are added to your environment variables, the request body can be
        read on standard input, and the resulting page is written to
        standard output.

        The CGI parameters are also passed as env, and the size of the
        request body in bytes is passed as bodysize (or zero if there is
        no body).

        Default implementation is to produce a text page listing the
        request's CGI parameters, which can be useful for debugging.
        """
        print("Content-Type: text/plain; charset=utf-8")
        print()
        for k, v in env.items():
            print("%s: %r" % (k, v))


