#!/usr/bin/env python3
#

import os, sys, socket
from scgi import passfd
import tempfile

#
# Create a pipe for sending the fd.
#

rfd, wfd = passfd.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
print("rfd", rfd, "wfd", wfd)

# We will pass this to the child
fileObj = tempfile.TemporaryFile()
line = b'Hello world!\n'
fileObj.write(line)
fileObj.flush()
fileObj.seek(0)

#
# fork() off!
#

pid = os.fork()

if pid != 0:
    # We're in the parent.

    # ioctl() will only pass raw filedescriptors. Find fd of fileObj.
    fd = fileObj.fileno()

    # Send to the child
    os.write(wfd, b'x')
    passfd.sendfd(wfd, fd)

    # Wait for child to terminate, then exit.
    os.waitpid(pid, 0)
    fileObj.close()
    sys.exit(0)

else:
    # We're in the child.

    fileObj.close()
    
    print(os.read(rfd, 1))
    fd = passfd.recvfd(rfd)

    # Reopen the filedescriptor as a Python File-object.
    fileObj = os.fdopen(fd, 'rb')

    # Example usage: Read file, print the first line.
    data = fileObj.readline()
    print("Read line: %r, expected %r" % (data, line))
    assert line == data
    sys.exit(0)

