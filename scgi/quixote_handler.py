#!/usr/bin/env python3
"""
A SCGI handler that uses Quixote to publish dynamic content.
"""

import sys
import time
import os
import getopt
import signal
from quixote import enable_ptl, publish
from . import scgi_server

pidfilename = None # set by main()

def debug(msg):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S",
                              time.localtime(time.time()))
    sys.stderr.write("[%s] %s\n" % (timestamp, msg))


class QuixoteHandler(scgi_server.SCGIHandler):

    # override in subclass
    publisher_class = publish.Publisher
    root_namespace = None
    prefix = ""

    def __init__(self, *args, **kwargs):
        debug("%s created" % self.__class__.__name__)
        scgi_server.SCGIHandler.__init__(self, *args, **kwargs)
        assert self.root_namespace, "You must provide a namespace to publish"
        self.publisher = self.publisher_class(self.root_namespace)

    def handle_connection (self, conn):
        input = conn.makefile("rb")
        output = conn.makefile("wb")

        env = self.read_env(input)

        # mod_scgi never passes PATH_INFO, fake it
        prefix = self.prefix
        path = env['SCRIPT_NAME']
        assert path[:len(prefix)] == prefix, (
                "path %r doesn't start with prefix %r" % (path, prefix))
        env['SCRIPT_NAME'] = prefix
        env['PATH_INFO'] = path[len(prefix):] + env.get('PATH_INFO', '')

        self.publisher.publish(input, output, sys.stderr, env)

        try:
            input.close()
            output.close()
            conn.close()
        except IOError as err:
            debug("IOError while closing connection ignored: %s" % err)

        if self.publisher.config.run_once:
            sys.exit(0)


class DemoHandler(QuixoteHandler):

    root_namespace = "quixote.demo"
    prefix = "/dynamic" # must match Location directive

    def __init__(self, *args, **kwargs):
        enable_ptl()
        QuixoteHandler.__init__(self, *args, **kwargs)


def change_uid_gid(uid, gid=None):
    "Try to change UID and GID to the provided values"
    # This will only work if this script is run by root.

    # Try to convert uid and gid to integers, in case they're numeric
    import pwd, grp
    try:
        uid = int(uid)
        default_grp = pwd.getpwuid(uid)[3]
    except ValueError:
        uid, default_grp = pwd.getpwnam(uid)[2:4]

    if gid is None:
        gid = default_grp
    else:
        try:
            gid = int(gid)
        except ValueError:
            gid = grp.getgrnam(gid)[2]

    os.setgid(gid)
    os.setuid(uid)


def term_signal(signum, frame):
    global pidfilename
    try:
        os.unlink(pidfilename)
    except OSError:
        pass
    sys.exit()

def main(handler=DemoHandler):
    usage = """Usage: %s [options]

    -F -- stay in foreground (don't fork)
    -P -- PID filename
    -l -- log filename
    -m -- max children
    -p -- TCP port to listen on
    -u -- user id to run under
    """ % sys.argv[0]
    nofork = 0
    global pidfilename
    pidfilename = "/var/tmp/quixote-scgi.pid"
    logfilename = "/var/tmp/quixote-scgi.log"
    max_children = 5    # scgi default
    uid = "nobody"
    port = 4000
    host = "127.0.0.1"
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'FP:l:m:p:u:')
    except getopt.GetoptError as exc:
        print(exc, file=sys.stderr)
        print(usage, file=sys.stderr)
        sys.exit(1)
    for o, v in opts:
        if o == "-F":
            nofork = 1
        elif o == "-P":
            pidfilename = v
        elif o == "-l":
            logfilename = v
        elif o == "-m":
            max_children = int(v)
        elif o == "-p":
            port = int(v)
        elif o == "-u":
            uid = v

    log = open(logfilename, "a", 1)
    os.dup2(log.fileno(), 1)
    os.dup2(log.fileno(), 2)
    os.close(0)

    if os.getuid() == 0:
        change_uid_gid(uid)

    if nofork:
        scgi_server.SCGIServer(handler, host=host, port=port,
                               max_children=max_children).serve()
    else:
        pid = os.fork()
        if pid == 0:
            pid = os.getpid()
            pidfile = open(pidfilename, 'w')
            pidfile.write(str(pid))
            pidfile.close()
            signal.signal(signal.SIGTERM, term_signal)
            try:
                scgi_server.SCGIServer(handler, host=host, port=port,
                                       max_children=max_children).serve()
            finally:
                # grandchildren get here too, don't let them unlink the pid
                if pid == os.getpid():
                    try:
                        os.unlink(pidfilename)
                    except OSError:
                        pass

if __name__ == '__main__':
    main()

