#!/usr/bin/env python
#

import os, sys, socket
from scgi import passfd

#
# Create a pipe for sending the fd.
#

rfd, wfd = passfd.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
print "rfd", rfd, "wfd", wfd


#
# fork() off!
#

pid = os.fork()

if pid != 0:
    # We're in the parent.

    # Open a file for passing along to child.
    
    fileObj = open('/dev/zero', 'r')

    # ioctl() will only pass raw filedescriptors. Find fd of fileObj.
    fd = fileObj.fileno()

    # Send to the child
    os.write(wfd, "x")
    passfd.sendfd(wfd, fd)

    # Wait for child to terminate, then exit.
    os.waitpid(pid, 0)
    sys.exit(0)

else:
    # We're in the child.
    
    print os.read(rfd, 1)
    fd = passfd.recvfd(rfd)

    # Reopen the filedescriptor as a Python File-object.
    fileObj = os.fdopen(fd, 'r')

    # Example usage: Read file, print the first line.
    print "first byte", `fileObj.read(1)`
    sys.exit(0)

