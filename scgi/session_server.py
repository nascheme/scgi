#!/usr/bin/env python3
"""
A pre-forking SCGI server that uses file descriptor passing to off-load
requests to child worker processes.

This version of the server tries to associate a process with each client
session.  Each client session has their requests processed in a FIFO fashion.
The main advantage is that clients that generate long running requests will
throttle themselves.  Hammering reload on an expensive to load page will not
result in multiple worker processes trying to generate the same page.
"""
import sys
import socket
import os
import select
import time
import errno
import fcntl
import signal
import re
import traceback
import io
from scgi import passfd
from scgi.util import SCGIHandler, log, ns_reads, parse_env
from scgi.systemd_socket import get_systemd_socket

def send_http_error(code, conn):
    # send a minimal HTTP error to the client.  We have to fork
    # because we don't want to block the whole server
    if code == 503:
        title = 'Service Temporarily Unavailable'
        body = ('The server is currently unable to handle '
                'the request due to a temporary overloading. '
                'Please try again later.')
    else:
        assert 0, 'unknown HTTP error code %r' % code
    pid = os.fork()
    if pid == 0:
        response = ('Status: {code}\r\n'
                    'Content-Type: text/html; charset="utf-8"\r\n'
                    '\r\n'
                    '<html><head>'
                    '<title>{title}</title>'
                    '</head><body>'
                    '<h1>{title}</h1>'
                    '{body}'
                    '</body>').format(code=code,
                                      title=title,
                                      body=body)
        conn.sendall(response.encode('iso-8859-1'))
        conn.close()
        sys.exit(0)
    else:
        conn.close()


class Child:

    MAX_QUEUE = 15

    def __init__(self, session_id, pid, fd):
        self.session_id = session_id
        self.pid = pid
        self.fd = fd
        self.queue = []
        self.closed = False
        self.last_used = time.time()

    def log(self, msg):
        log('%s (pid=%s)' % (msg, self.pid))

    def get_age(self):
        return (time.time() - self.last_used)

    def close(self):
        if not self.closed:
            os.close(self.fd)
            for conn in self.queue:
                conn.close()
            del self.queue[:]
            self.closed = True

    def queue_request(self, conn):
        if len(self.queue) >= self.MAX_QUEUE:
            # queue is getting too long, start returning busy errors
            # rather than continuing to queue requests up
            self.log('server busy error')
            send_http_error(503, conn)
        else:
            self.queue.append(conn)

    def process(self):
        assert not self.closed
        assert self.queue
        conn = self.queue[0]
        if len(self.queue) > 1:
            self.log('queued request, qlen=%s' % len(self.queue))
        # Try to read the single byte written by the child.
        # This can fail if the child died or the pipe really
        # wasn't ready (select returns a hint only).  The fd has
        # been made non-blocking by spawn_child.
        try:
            ready_byte = os.read(self.fd, 1)
            if not ready_byte:
                raise IOError('null read from child')
            assert ready_byte == b'1', repr(ready_byte)
        except (OSError, IOError) as exc:
            if exc.errno  == errno.EWOULDBLOCK:
                # select was wrong and fd not ready.  Child might
                # still be busy so keep it alive (don't close).
                return
            self.log('error while getting child status: %s' % exc)
        else:
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
                self.last_used = time.time()
                conn.close()
                del self.queue[0]
                return
        # We have failed to pass the fd to the child.  Since the
        # child is not behaving how we expect, we close 'fd'.  That
        # will cause the child to die (if it hasn't already).  We will
        # reap the exit status in reap_children() and remove the Child()
        # object from the 'children' list.
        self.close()


class SCGIServer:

    DEFAULT_PORT = 4000

    # pattern to match session cookie.  The default pattern works
    # for Quixote session IDs.  Tweaking of the pattern may be
    # required.
    SESSION_ID_PATTERN = r'session="(?P<id>[A-Za-z0-9\\/_=+-]+)"'
    DEFAULT_SESSION_ID = '*unknown*'

    MAX_AGE = 7200
    CHILD_TIMEOUT = 600

    def __init__(self, handler_class=SCGIHandler, host="", port=DEFAULT_PORT,
                 max_children=5):
        self.handler_class = handler_class
        self.host = host
        self.port = port
        self.max_children = max_children
        self.children = {} # {session_id : Child}
        self.last_prune = 0
        self.restart = 0

    #
    # Deal with a hangup signal.  All we can really do here is
    # note that it happened.
    #
    def hup_signal(self, signum, frame):
        log('got HUP signal, scheduling restart')
        self.restart = 1

    def spawn_child(self, session_id, conn=None):
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
            for child in self.children.values():
                child.close()
            self.handler_class(parent_fd).serve()
            sys.exit(0)
        else:
            os.close(parent_fd)
            self.children[session_id] = child = Child(session_id, pid, child_fd)
            log('started child (session=%s pid=%s nchild=%s)' %
                                (session_id, pid, len(self.children)))
            return child

    def get_child(self, pid):
        for child in self.children.values():
            if child.pid == pid:
                return child
        return None

    def do_stop(self):
        # Close connections to the children, which will cause them to exit
        # after finishing what they are doing.
        for child in self.children.values():
            child.close()

    def do_restart(self):
        log('restarting child processes')
        self.do_stop()
        self.restart = 0

    def extract_session_id(self, conn):
        """Find a session indentifier for the current request.  Return
        the ID and the SCGI environment dictionary.
        """
        # we have to be careful here, we don't want to block the server
        # processing look while waiting on sockets.  In practice this
        # implementation seems to work well (tested with nginx and Apache).
        env = {}
        # select is necessary since even with MSG_PEEK the recv() can block
        # if there is no data available
        r, w, e = select.select([conn], [], [], 0.2)
        if r:
            headers = conn.recv(4096, socket.MSG_PEEK)
            headers = ns_reads(io.BytesIO(headers))
            env = parse_env(headers)
            cookies = env.get('HTTP_COOKIE')
            if cookies:
                m = re.search(self.SESSION_ID_PATTERN, cookies)
                if m:
                    return m.group('id'), env
        else:
            log('gave up waiting to peek at session id')
        ip = env.get('HTTP_X_FORWARDED_FOR') or env.get('REMOTE_ADDR')
        if ip:
            return ip, env
        try:
            return conn.getpeername()[0], env
        except socket.error:
            return self.DEFAULT_SESSION_ID, env

    def delegate_request(self, conn):
        """Pass a request fd to a child process to handle.
        """
        try:
            session_id, env = self.extract_session_id(conn)
        except Exception:
            log('error extracting session id, traceback follows')
            traceback.print_exc(file=sys.stderr)
            session_id = self.DEFAULT_SESSION_ID
            env = {}
        child = self.children.get(session_id)
        if child is None or child.closed:
            child = self.spawn_child(session_id, conn)
        log('process pid=%s %s %s %s' % (
                    child.pid,
                    env.get('REMOTE_ADDR'),
                    env.get('REQUEST_METHOD'),
                    env.get('REQUEST_URI')))
        child.queue_request(conn)

    def get_listening_socket(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host, self.port))
        return s

    def reap_children(self):
        while 1:
            try:
                (pid, status) = os.waitpid(-1, os.WNOHANG)
            except OSError:
                break # no child process?
            if pid <= 0:
                break
            child = self.get_child(pid)
            if child is not None:
                child.close()
                del self.children[child.session_id]

    def process_children(self, ready_fds):
        reap = False
        for child in self.children.values():
            if child.closed:
                reap = True
            elif child.queue and child.fd in ready_fds:
                child.process()
        if reap:
            self.reap_children()

    def _is_old(self, child):
        max_age = max(10, self.MAX_AGE / len(self.children))
        age = child.get_age()
        if age < max_age:
            return False # used recently
        if age > self.CHILD_TIMEOUT:
            return True # been around too long, kill it with impunity
        if child.queue:
            return False # waiting connections, let it live
        r, w, e = select.select([child.fd], [], [], 0)
        if r:
            return True # old and not busy
        else:
            return False # old but busy, timeout not expired yet

    def prune_children(self):
        n = len(self.children)
        if n == 0:
            return
        now = time.time()
        if now - self.last_prune < 20:
            return
        self.last_prune = now
        for child in list(self.children.values()):
            if self._is_old(child):
                log('closed old child (pid=%s nchild=%s)' %
                                       (child.pid, len(self.children)-1))
                child.close()
                del self.children[child.session_id]
        self.reap_children()

    def get_waiting_sockets(self):
        fds = [self.socket]
        for child in self.children.values():
            if child.queue:
                fds.append(child.fd)
        return fds

    def serve_on_socket(self, s):
        self.socket = s
        self.socket.listen(40)
        signal.signal(signal.SIGHUP, self.hup_signal)
        last_prune = time.time()
        while 1:
            try:
                r, w, e = select.select(self.get_waiting_sockets(), [], [], 5)
            except select.error as e:
                if e.errno == errno.EINTR:
                    continue
                raise  # something weird
            if self.restart:
                self.do_restart()
            self.prune_children()
            if self.socket in r:
                try:
                    conn, addr = self.socket.accept()
                    self.delegate_request(conn)
                except socket.error as exc:
                    if exc.errno != errno.EINTR:
                        raise # something weird
                r.remove(self.socket)
            if r:
                self.process_children(r)


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
