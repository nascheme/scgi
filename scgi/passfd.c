/*
 * Passing file descriptions with Python.  Tested with Linux and FreeBSD.
 * Should also work on Solaris.  Portability fixes or success stories welcome.
 *
 * Neil Schemenauer <nas@arctrix.com>
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

/* for platforms that don't provide CMSG_*  macros */
#ifndef ALIGNBYTES
#define ALIGNBYTES (sizeof(int) - 1)
#endif

#ifndef ALIGN
#define ALIGN(p) (((unsigned int)(p) + ALIGNBYTES) & ~ ALIGNBYTES)
#endif

#ifndef CMSG_LEN
#define CMSG_LEN(len) (ALIGN(sizeof(struct cmsghdr)) + ALIGN(len))
#endif

#ifndef CMSG_SPACE
#define CMSG_SPACE(len) (ALIGN(sizeof(struct cmsghdr)) + ALIGN(len))
#endif


static int
recv_fd(int sockfd)
{
	ssize_t rv;
	char tmp[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg;
	struct iovec iov;
	struct msghdr msg;
	char ch = '\0';

	memset(&msg, 0, sizeof(msg));
	iov.iov_base = &ch;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = tmp;
	msg.msg_controllen = sizeof(tmp);

	Py_BEGIN_ALLOW_THREADS
	rv = recvmsg(sockfd, &msg, 0);
	Py_END_ALLOW_THREADS
	if (rv <= 0) {
		return -1;
	}
	cmsg = CMSG_FIRSTHDR(&msg);
	return *(int *) CMSG_DATA(cmsg);
}

static int
send_fd (int sockfd, int fd)
{
	ssize_t rv;
	char tmp[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg;
	struct iovec iov;
	struct msghdr msg;
	char ch = '\0';

	memset(&msg, 0, sizeof(msg));
	msg.msg_control = (caddr_t) tmp;
	msg.msg_controllen = CMSG_LEN(sizeof(int));
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	*(int *)CMSG_DATA(cmsg) = fd;
	iov.iov_base = &ch;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	Py_BEGIN_ALLOW_THREADS
	rv = sendmsg(sockfd, &msg, 0);
	Py_END_ALLOW_THREADS
	if (rv != 1)
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

static char recvfd_doc [] = "recvfd(sockfd) -> fd";

static PyObject *
passfd_recvfd(PyObject *self, PyObject *args)
{
	int sockfd, fd;

	if (!PyArg_ParseTuple(args, "i:recvfd", &sockfd))
		return NULL;

	if ((fd = recv_fd(sockfd)) < 0) {
		PyErr_SetFromErrno(PyExc_IOError);
		return NULL;
	}

	return PyLong_FromLong((long) fd);
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

static char passfd_doc [] = "Pass file descriptors using socket pairs";

/* List of functions */

static PyMethodDef passfd_methods[] = {
	{"sendfd",	passfd_sendfd, METH_VARARGS, sendfd_doc},
	{"recvfd",	passfd_recvfd, METH_VARARGS, recvfd_doc},
	{"socketpair",	passfd_socketpair, METH_VARARGS, socketpair_doc},
	{NULL, NULL, 0, NULL}		/* sentinel */
};


static struct PyModuleDef passfd_module = {
	PyModuleDef_HEAD_INIT,
	"passfd",
	passfd_doc,
	-1,
	passfd_methods,
    NULL,
    NULL,
    NULL,
    NULL,
};

PyMODINIT_FUNC PyInit_passfd(void)
{
    PyObject *m = PyModule_Create(&passfd_module);
    return m;
};


