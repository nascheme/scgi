#!/usr/bin/env python3
"""
A pre-forking SCGI server that uses file descriptor passing to off-load
requests to child worker processes.
"""

import sys
import socket
import os
import select
import errno
import fcntl
import signal
from scgi import passfd
from scgi.util import SCGIHandler, log
from scgi.systemd_socket import get_systemd_socket


class Child:
    def __init__(self, pid, fd):
        self.pid = pid
        self.fd = fd
        self.closed = 0

    def close(self):
        if not self.closed:
            os.close(self.fd)
        self.closed = 1

    def log(self, msg):
        log('%s (pid=%s)' % (msg, self.pid))

    def process(self, conn):
        # Try to read the single byte written by the child.
        # This can fail if the child died or the socket really
        # wasn't ready (select returns a hint only).  The fd has
        # been made non-blocking by spawn_child.
        try:
            ready_byte = os.read(self.fd, 1)
            if not ready_byte:
                raise IOError('null read from child')
            assert ready_byte == b"1", repr(ready_byte)
        except (OSError, IOError) as exc:
            if exc.errno  == errno.EWOULDBLOCK:
                # select was wrong and fd not ready.  Child might
                # still be busy so keep it alive (don't close).
                return False
            else:
                self.log('error while getting child status: %s' % exc)
        else:
            # The byte was read okay, now we need to pass the fd
            # of the request to the child.  This can also fail
            # if the child died.  Again, if this fails we fall
            # through to the "reap_children" logic and will
            # retry the select call.
            try:
                passfd.sendfd(self.fd, conn.fileno())
            except IOError as exc:
                if exc.errno == errno.EPIPE:
                    # broken pipe, child died?
                    self.log('EPIPE passing fd to child')
                else:
                    # some other error that we don't expect
                    self.log('IOError passing fd to child: %s' % exc.errno)
            else:
                # fd was apparently passed okay to the child.
                # The child could die before completing the
                # request but that's not our problem anymore.
                return True
        # We have failed to pass the fd to the child.  Since the
        # child is not behaving how we expect, we close 'fd'.  That
        # will cause the child to die (if it hasn't already).  We will
        # reap the exit status in reap_children() and remove the Child()
        # object from the 'children' list.
        self.close()
        return False # did not pass fd successfully


class SCGIServer:

    DEFAULT_PORT = 4000

    def __init__(self, handler_class=SCGIHandler, host="", port=DEFAULT_PORT,
                 max_children=5):
        self.handler_class = handler_class
        self.host = host
        self.port = port
        self.max_children = max_children
        self.children = []
        self.restart = 0

    #
    # Deal with a hangup signal.  All we can really do here is
    # note that it happened.
    #
    def hup_signal(self, signum, frame):
        log('got HUP signal, scheduling restart')
        self.restart = 1

    def spawn_child(self, conn=None):
        parent_fd, child_fd = passfd.socketpair(socket.AF_UNIX,
                                                socket.SOCK_STREAM)
        # make child fd non-blocking
        flags = fcntl.fcntl(child_fd, fcntl.F_GETFL, 0)
        fcntl.fcntl(child_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        pid = os.fork()
        if pid == 0:
            if conn is not None:
                conn.close() # in the midst of handling a request, close
                             # the connection in the child
            os.close(child_fd)
            self.socket.close()
            for child in self.children:
                child.close()
            self.handler_class(parent_fd).serve()
            sys.exit(0)
        else:
            os.close(parent_fd)
            self.children.append(Child(pid, child_fd))
            log('started child (pid=%s nchild=%s)' % (pid, len(self.children)))

    def get_child(self, pid):
        for child in self.children:
            if child.pid == pid:
                return child
        return None

    def reap_children(self):
        while self.children:
            (pid, status) = os.waitpid(-1, os.WNOHANG)
            if pid <= 0:
                break
            child = self.get_child(pid)
            child.close()
            self.children.remove(child)

    def do_stop(self):
        # Close connections to the children, which will cause them to exit
        # after finishing what they are doing.
        for child in self.children:
            child.close()

    def do_restart(self):
        log('restarting child processes')
        self.do_stop()
        self.restart = 0

    def delegate_request(self, conn):
        """Pass a request fd to a child process to handle.  This method
        blocks if all the children are busy and we have reached the
        max_children limit."""

        # There lots of subtleties here.  First, to determine the readiness
        # of a child we can't use the writable status of the Unix domain
        # socket connected to the child, since select will return true
        # if the buffer is not filled.  Instead, each child writes one
        # byte of data when it is ready for a request.  The normal case
        # is that a child is ready for a request.  We want that case to
        # be fast.  Also, we want to pass requests to the same child if
        # possible.  Finally, we need to gracefully handle children
        # dying at any time.

        # If no children are ready and we haven't reached max_children
        # then we want another child to be started without delay.
        timeout = 0

        # Number of times to retry delegating request.  If no child can
        # be found after those tries, give up.  In that case 'conn' will
        # be closed without handling it.
        retry_count = 30

        for i in range(retry_count):
            fds = [child.fd for child in self.children if not child.closed]
            r, w, e = select.select(fds, [], [], timeout)
            if r:
                # One or more children look like they are ready.  Sort
                # the file descriptions so that we keep preferring the
                # same child.
                child = None
                for child in self.children:
                    if not child.closed and child.fd in r:
                        break
                if child is None:
                    continue # no child found, should not get here
                if child.process(conn):
                    return # passed fd to child, we are done

            # didn't find any child, check if any died
            self.reap_children()

            # start more children if we haven't met max_children limit
            if len(self.children) < self.max_children:
                self.spawn_child(conn)

            # Start blocking inside select.  We might have reached
            # max_children limit and they are all busy.
            timeout = 2
        log('failed to delegate request %s' % conn)

    def get_listening_socket(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host, self.port))
        return s

    def serve_on_socket(self, s):
        self.socket = s
        self.socket.listen(40)
        signal.signal(signal.SIGHUP, self.hup_signal)
        while 1:
            conn, addr = self.socket.accept()
            self.delegate_request(conn)
            conn.close()
            if self.restart:
                self.do_restart()

    def serve(self):
        sock = get_systemd_socket()
        if sock is not None:
            log('Using inherited socket %r' % (sock.getsockname(),))
        else:
            sock = self.get_listening_socket()
        self.serve_on_socket(sock)


def main():
    if len(sys.argv) == 2:
        port = int(sys.argv[1])
    else:
        port = SCGIServer.DEFAULT_PORT
    SCGIServer(port=port).serve()

if __name__ == "__main__":
    main()
