/*
 * Passing file descriptions with Python.  Tested with Linux and FreeBSD.
 * Should also work on Solaris.  Portability fixes or success stories welcome.
 *
 * Neil Schemenauer <nas@mems-exchange.org>
 */

#include "Python.h"

#ifndef __OpenBSD__
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 500
#endif
#ifndef _XOPEN_SOURCE_EXTENDED
#define _XOPEN_SOURCE_EXTENDED 1 /* Solaris <= 2.7 needs this too */
#endif
#endif /* __OpenBSD__ */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <stddef.h>


#define CONTROLLEN sizeof (struct cmsghdr) + sizeof (void*)

static int
recv_fd(int sockfd)
{
	char tmpbuf[CONTROLLEN];
	struct cmsghdr *cmptr = (struct cmsghdr *) tmpbuf;
	struct iovec iov[1];
	struct msghdr msg;
	void* buf[1];

	memset(tmpbuf, 0, CONTROLLEN);
	iov[0].iov_base = buf;
	iov[0].iov_len = sizeof (buf);
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	msg.msg_name = NULL;
	msg.msg_namelen = 0;

	msg.msg_control = cmptr;
	msg.msg_controllen = CONTROLLEN;

	if (recvmsg(sockfd, &msg, 0) <= 0)
		return -1;

	return *(int *) CMSG_DATA (cmptr);
}

static int
send_fd (int sockfd, int fd)
{
	char tmpbuf[CONTROLLEN];
	struct cmsghdr *cmptr = (struct cmsghdr *) tmpbuf;
        struct iovec iov[1];
        struct msghdr msg;
        void* buf[1];

        iov[0].iov_base = buf;
        iov[0].iov_len = 1;
        msg.msg_iov = iov;
        msg.msg_iovlen = 1;
        msg.msg_name = NULL;
        msg.msg_namelen = 0;
        msg.msg_control = cmptr;
        msg.msg_controllen = CONTROLLEN;

        cmptr->cmsg_level = SOL_SOCKET;
        cmptr->cmsg_type = SCM_RIGHTS;
        cmptr->cmsg_len = CONTROLLEN;
        *(int *)CMSG_DATA (cmptr) = fd;

        if (sendmsg(sockfd, &msg, 0) != 1)
                return -1;

        return 0;
}


static char sendfd_doc [] =
"sendfd(sockfd, fd)";

static PyObject *
passfd_sendfd(PyObject *self, PyObject *args)
{
	int sockfd, fd;

	if (!PyArg_ParseTuple(args, "ii:sendfd", &sockfd, &fd))
		return NULL;

	if (send_fd(sockfd, fd) < 0) {
		PyErr_SetFromErrno(PyExc_IOError);
		return NULL;
	}

	Py_INCREF(Py_None);
	return Py_None;
}

static char recvfd_doc [] =
"recvfd(sockfd) -> fd";

static PyObject *
passfd_recvfd(PyObject *self, PyObject *args)
{
	int sockfd, fd;

	if (!PyArg_ParseTuple(args, "i:revcfd", &sockfd))
		return NULL;

	if ((fd = recv_fd(sockfd)) < 0) {
		PyErr_SetFromErrno(PyExc_IOError);
		return NULL;
	}

	return PyInt_FromLong((long) fd);
}

static char socketpair_doc [] =
"socketpair(family, type, proto=0) -> (fd, fd)";

static PyObject *
passfd_socketpair(PyObject *self, PyObject *args)
{
	int family, type, proto=0;
	int fd[2];

	if (!PyArg_ParseTuple(args, "ii|i:socketpair", &family, &type, &proto))
		return NULL;

	if (socketpair(family, type, proto, fd) < 0) {
		PyErr_SetFromErrno(PyExc_IOError);
		return NULL;
	}

	return Py_BuildValue("(ii)", (long) fd[0], (long) fd[1]);
}


/* List of functions */

static PyMethodDef passfd_methods[] = {
	{"sendfd",	passfd_sendfd, METH_VARARGS, sendfd_doc},
	{"recvfd",	passfd_recvfd, METH_VARARGS, recvfd_doc},
	{"socketpair",	passfd_socketpair, METH_VARARGS, socketpair_doc},
	{NULL,		NULL}		/* sentinel */
};


DL_EXPORT(void)
initpassfd(void)
{
	PyObject *m;

	/* Create the module and add the functions and documentation */
	m = Py_InitModule3("passfd", passfd_methods, NULL);

}
