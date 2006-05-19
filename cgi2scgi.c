/*
 * cgi2scgi: A CGI to SCGI translator
 *
 */

/* configuration settings */
#ifndef HOST
#define HOST "127.0.0.1"
#endif

#ifndef PORT
#define PORT 4000
#endif


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h> /* for TCP_NODELAY */

#define SCGI_PROTOCOL_VERSION "1"


struct scgi_header {
	struct scgi_header *next;
	char *name;
	char *value;
};

extern char **environ;

static void
die(void)
{
	_exit(2);
}

static void
die_perror(char *msg)
{
	char buf[500];
	snprintf(buf, sizeof buf, "error: %s", msg);
	perror(buf);
	die();
}

static void
die_msg(char *msg)
{
	fprintf(stderr, "error: %s\n", msg);
	die();
}

static int
open_socket(void)
{
	int sock, set;
	int tries = 4, retrytime = 1;
	struct in_addr host;
	struct sockaddr_in addr;

	/* create socket */
	if (!inet_aton(HOST, &(host))) {
		die_perror("parsing host IP");
	}

	addr.sin_addr = host;
	addr.sin_port = htons(PORT);
	addr.sin_family = AF_INET;

retry:
	sock = socket(PF_INET, SOCK_STREAM, 0);
	if (sock == -1) {
		die_perror("creating socket");
	}

	/* connect */
	if (connect(sock, (struct sockaddr *)&addr, sizeof addr) == -1) {
		close(sock);
		if (errno == ECONNREFUSED && tries > 0) {
			sleep(retrytime);
			tries--;
			retrytime *= 2;
			goto retry;
		}
		die_perror("connecting to server");
	}

#ifdef TCP_NODELAY
	/* disable Nagle */
	set = 1;
	setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&set, sizeof(set));
#endif

	return sock;
}

static int
send_headers(FILE *fp)
{
	int n;
	char **p;

	/* set the CONTENT_LENGTH header if it is not already set */
	if (setenv("CONTENT_LENGTH", "0", 0) < 0) return 0;
	if (setenv("SCGI", SCGI_PROTOCOL_VERSION, 1) < 0) return 0;

	/* calculate the total length of the headers */
	n = 0;
	for (p = environ; *p != NULL; *p++) {
		if (strchr(*p, '=') == NULL)
			continue;
		n += strlen(*p) + 1;
	}

	/* send header data as netstring */
	if (fprintf(fp, "%u:", n) < 0) return 0;
	if (fputs("CONTENT_LENGTH", fp) < 0) return 0;
	if (fputc('\0', fp) == EOF) return 0;
	if (fputs(getenv("CONTENT_LENGTH"), fp) < 0) return 0;
	if (fputc('\0', fp) == EOF) return 0;
	for (p = environ; *p != NULL; *p++) {
		char *eq = strchr(*p, '=');
		if (eq == NULL)
			continue;
		if (!strncmp(*p, "CONTENT_LENGTH=", 15))
			continue;
		n = eq - *p;
		if (fwrite(*p, 1, n, fp) < n)
			return 0;
		if (fputc('\0', fp) == EOF) return 0;
		if (fputs(eq + 1, fp) < 0) return 0;
		if (fputc('\0', fp) == EOF) return 0;
	}
	if (fputc(',', fp) == EOF) return 0;
	return 1;
}

static int
copyfp(FILE *in, FILE *out)
{
	size_t n, n2;
	char buf[8000];
	for (;;) {
		n = fread(buf, 1, sizeof buf, in);
		if (n != sizeof buf && ferror(in))
			return 0;
		if (n == 0)
			break; /* EOF */
		n2 = fwrite(buf, 1, n, out);
		if (n2 != n)
			return 0;
	}
	return 1;
}

int main(int argc, char **argv)
{
	int sock, fd;
	FILE *fp;

	sock = open_socket();

	/* send request */
	if ((fd = dup(sock)) < 0)
		die_perror("duplicating fd");
	if ((fp = fdopen(fd, "w")) == NULL)
		die_perror("creating buffered file");
	if (!send_headers(fp)) {
		die_msg("sending request headers");
	}
	if (!copyfp(stdin, fp)) {
		die_msg("sending request body");
	}
	if (fclose(fp) != 0)
		die_perror("sending request body");

	/* send reponse */
	if ((fd = dup(sock)) < 0 || (fp = fdopen(fd, "r")) == NULL)
		die_perror("creating buffered file from socket");
	if (!copyfp(fp, stdout)) {
		die_msg("sending response");
	}
	if (fclose(fp) != 0)
	    die_perror("closing socket");

	return 0;
}
