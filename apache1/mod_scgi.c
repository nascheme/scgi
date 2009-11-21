#define MOD_SCGI_VERSION "1.14"
#define SCGI_PROTOCOL_VERSION "1"
/* #define VERBOSE_DEBUG */


#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_script.h"

#include <netinet/tcp.h> /* for TCP_NODELAY */

#define UNSET 0
#define ENABLED 1
#define DISABLED 2

typedef struct {
	char *path;
	unsigned long addr;	/* address in network byte order */
	unsigned short port;	/* port in network byte order */
} mount_entry;

/*
 * Configuration record.  Used per-directory configuration data.
 */
typedef struct {
	mount_entry mount;
	int enabled;		/* mod_scgi enabled from this directory */
} scgi_cfg;

/* Server level configuration */
typedef struct {
	array_header *mounts;
} scgi_server_cfg;

/*
 * Declare ourselves so the configuration routines can find and know us.
 * We'll fill it in at the end of the module.
 */
module MODULE_VAR_EXPORT scgi_module;

/*
 * Locate our directory configuration record for the current request.
 */
static scgi_cfg *our_dconfig(request_rec *r)
{
	return (scgi_cfg *) ap_get_module_config(r->per_dir_config,
						 &scgi_module);
}

static scgi_server_cfg *our_sconfig(server_rec *s)
{
    return (scgi_server_cfg *) ap_get_module_config(s->module_config,
						    &scgi_module);
}

static int
mount_entry_matches(char *url, char *prefix, char **path_info)
{
	int i;
	for (i=0; prefix[i] != '\0'; i++) {
		if (url[i] == '\0' || url[i] != prefix[i])
			return 0;
	}
	if (url[i] == '\0' || url[i] == '/') {
		*path_info = url + i;
		return 1;
	}
	return 0;
}

static int scgi_trans(request_rec *r)
{
	scgi_cfg *cfg = our_dconfig(r);
	scgi_server_cfg *scfg = our_sconfig(r->server);
	if (cfg->enabled == DISABLED) {
		return DECLINED;
	}
	if (cfg->mount.addr != UNSET) {
		r->handler = "scgi-handler";
		return OK;
	}
	else {
    		int i;
    		mount_entry *entries = (mount_entry *) scfg->mounts->elts;
		for (i = 0; i < scfg->mounts->nelts; ++i) {
			char *path_info;
			mount_entry *p = &entries[i];
			if (mount_entry_matches(r->uri, p->path, &path_info)) {
				r->handler = "scgi-handler";
				r->path_info = path_info;
				ap_set_module_config(r->request_config,
						     &scgi_module,
						     p);
				return OK;
			}
		}
	}
	return DECLINED;
}

int open_socket(request_rec *r)
{
	int retries, sleeptime, rv;
	struct sockaddr_in addr;
	int sock;
	scgi_cfg *cfg = our_dconfig(r);
	mount_entry *p = (mount_entry *) ap_get_module_config(r->request_config,
							      &scgi_module);
	if (!p) {
		p = &cfg->mount;
	}

	if (p->addr == UNSET)
		addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	else
		addr.sin_addr.s_addr = p->addr;
	if (p->port == UNSET)
		addr.sin_port = htons(4000);
	else
		addr.sin_port = p->port;
	addr.sin_family = AF_INET;

	/* try to connect */
	retries = 4;
	sleeptime = 1;

restart:
	/* create the socket */
	sock = ap_psocket(r->pool, AF_INET, SOCK_STREAM, 0);
	if (sock == -1) 
		return -1;
  
	rv = connect(sock, (struct sockaddr *)&addr, sizeof addr);
	if (rv != 0) {
		ap_pclosesocket(r->pool, sock);
		if (errno == EINTR)
			goto restart; /* signals suck */
		if (errno == ECONNREFUSED && retries > 0) {
			/* server may be temporarily down, retry */
			ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r,
				      "scgi: connection refused, retrying");
			sleep(sleeptime);
			--retries;
			sleeptime *= 2;
			goto restart;
		}
		ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
			      "scgi: connecting to server");
		return -1;
	}

#ifdef TCP_NODELAY
	if (addr.sin_family == AF_INET) {
		/* disable Nagle */
		int set = 1;
		setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&set, sizeof(set));
	}
#endif

	return sock;
}

static char *http2env(pool *p, const char *name)
{
	char *env_name = ap_pstrcat(p, "HTTP_", name, NULL);
	char *cp;

	for (cp = env_name + 5; *cp != 0; cp++) {
		if (*cp == '-') {
			*cp = '_';
		}
		else {
			*cp = ap_toupper(*cp);
		}
	}

	return env_name;
}


static char *lookup_name(table *t, const char *name)
{
	array_header *hdrs_arr;
	table_entry *hdrs;
	int i;

	hdrs_arr = ap_table_elts(t);
	hdrs = (table_entry *)hdrs_arr->elts;
	for (i = 0; i < hdrs_arr->nelts; ++i) {
		if (hdrs[i].key == NULL) {
			continue;
		}
		if (strcasecmp(hdrs[i].key, name) == 0) {
			return hdrs[i].val;
		}
	}
	return NULL;
}

static char *lookup_header(request_rec *r, const char *name)
{
	return lookup_name(r->headers_in, name);
}

static char *original_uri(request_rec *r)
{
	char *first, *last;

	if (r->the_request == NULL) {
		return (char *) ap_pcalloc(r->pool, 1);
	}

	first = r->the_request;     /* use the request-line */

	while (*first && !ap_isspace(*first)) {
		++first;                /* skip over the method */
	}
	while (ap_isspace(*first)) {
		++first;                /*   and the space(s)   */
	}

	last = first;
	while (*last && !ap_isspace(*last)) {
		++last;                 /* end at next whitespace */
	}

	return ap_pstrndup(r->pool, first, last - first);
}

static void log_err(request_rec *r, const char *msg)
{
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
			"scgi: %s", msg);
}

static void log_debug(request_rec *r, const char *msg)
{
#ifdef VERBOSE_DEBUG
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r,
			"scgi: %s", msg);
#endif
}

static void add_header(table *t, const char *name, const char *value)
{
	if (name != NULL && value != NULL) {
		ap_table_addn(t, name, value);
	}
}

static int send_headers(request_rec *r, BUFF *f)
{
	table *t;
	array_header *hdrs_arr, *env_arr;
	table_entry *hdrs, *env;
	int i;
	unsigned long n;

	log_debug(r, "sending headers");
	t = ap_make_table(r->pool, 40); /* headers to send */
	if (!t)
		return 0;
	/* CONTENT_LENGTH must come first and always be present */
	add_header(t, "CONTENT_LENGTH",
		   	ap_psprintf(r->pool, "%ld", r->remaining));
	add_header(t, "SCGI", SCGI_PROTOCOL_VERSION);
	add_header(t, "SERVER_SOFTWARE", ap_get_server_version());
	add_header(t, "SERVER_PROTOCOL", r->protocol);
	add_header(t, "SERVER_NAME", ap_get_server_name(r));
	add_header(t, "SERVER_ADMIN", r->server->server_admin);
	add_header(t, "SERVER_ADDR", r->connection->local_ip);
	add_header(t, "SERVER_PORT",
			ap_psprintf(r->pool, "%u", ap_get_server_port(r)));
	add_header(t, "REMOTE_ADDR", r->connection->remote_ip);
	add_header(t, "REMOTE_PORT",
			ap_psprintf(r->pool, "%d",
				ntohs(r->connection->remote_addr.sin_port)));
	add_header(t, "REMOTE_USER", r->connection->user);
	add_header(t, "REQUEST_METHOD", r->method);
	add_header(t, "REQUEST_URI", original_uri(r));
	add_header(t, "QUERY_STRING", r->args ? r->args : "");
	if (r->path_info) {
		/*
		This request uri apparently matched one of the mount points.
		We want the matching mount point to be the SCRIPT_NAME, always.
		We want the rest of the uri to be the PATH_INFO, always.
		Under certain apache configurations, r->path_info is modified
		between the time the match is found and the scgi handler is
		called, so we go back to the matching mount entry to make sure
		that we get the right SCRIPT_NAME, and we use it to find the
		corresponding value for PATH_INFO.
		*/
		mount_entry *entry;
		entry = ap_get_module_config(r->request_config, &scgi_module);
		if (entry) {
			char *mount_point;
			char *path_info;
			mount_point = entry->path;
			mount_entry_matches(r->uri, mount_point, &path_info);
			add_header(t, "SCRIPT_NAME", mount_point);
			add_header(t, "PATH_INFO", path_info);
		}
		else {
			/* skip PATH_INFO, don't know it */
			add_header(t, "SCRIPT_NAME", r->uri);
		}
	}
	else {
		/* skip PATH_INFO, don't know it */
		add_header(t, "SCRIPT_NAME", r->uri);
	}
	add_header(t, "CONTENT_TYPE", lookup_header(r, "Content-type"));
	add_header(t, "DOCUMENT_ROOT", ap_document_root(r));

        /* HTTP headers */
	hdrs_arr = ap_table_elts(r->headers_in);
	hdrs = (table_entry *) hdrs_arr->elts;
	for (i = 0; i < hdrs_arr->nelts; ++i) {
		if (!hdrs[i].key)
			continue;
		add_header(t, http2env(r->pool, hdrs[i].key), hdrs[i].val);
	}

        /* environment variables */
        env_arr = ap_table_elts(r->subprocess_env);
        env = (table_entry *)env_arr->elts;
        for (i = 0; i < env_arr->nelts; ++i) {
		add_header(t, env[i].key, env[i].val);
        }

	hdrs_arr = ap_table_elts(t);
	hdrs = (table_entry *)hdrs_arr->elts;
	/* calculate length of header data (including nulls) */
	n = 0;
	for (i = 0; i < hdrs_arr->nelts; ++i) {
		n += strlen(hdrs[i].key) + 1;
		n += strlen(hdrs[i].val) + 1;
	}

	/* send header data as netstring */
	if (ap_bprintf(f, "%lu:", n) < 0) {
		return 0;
	}
	for (i = 0; i < hdrs_arr->nelts; ++i) {
		if (ap_bputs(hdrs[i].key, f) < 0) return 0;
		if (ap_bputc('\0', f) < 0) return 0;
		if (ap_bputs(hdrs[i].val, f) < 0) return 0;
		if (ap_bputc('\0', f) < 0) return 0;
	}
	if (ap_bputc(',', f) < 0) return 0;

	return 1;
}

static int send_request_body (request_rec *r, BUFF *f)
{
	if (ap_should_client_block(r)) {
		int n;
		char buffer[HUGE_STRING_LEN];
		while ((n = ap_get_client_block(r, buffer,
						sizeof buffer)) > 0) {
			if (ap_bwrite(f, buffer, n) != n) return 0;
			ap_reset_timeout(r);
		}
	}
	if (ap_bflush(f) < 0) return 0;
	return 1;
}

static int scgi_handler(request_rec *r)
{
	int ret, sock;
	BUFF *f;
	char *request_body = NULL;
	const char *location;

	if (strcmp(r->handler, "scgi-handler"))
		return DECLINED;

	if ((ret = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR))) {
		return ret;
	}
	
	/* connect to scgi server */
	ap_hard_timeout("scgi connect", r);
	log_debug(r, "connecting to server");
	sock = open_socket(r);
	if (sock == -1) {
		if (request_body)
			free(request_body);
		return SERVER_ERROR;
	}
	ap_kill_timeout(r);

	f = ap_bcreate(r->pool, B_RDWR | B_SOCKET);
	ap_bpushfd(f, sock, sock);

	ap_hard_timeout("scgi sending request", r);

	/* send headers */
        if (!send_headers(r, f)) {
		log_err(r, "error sending response headers");
		return SERVER_ERROR;
	}

	/* send request data */
	if (!send_request_body(r, f)) {
		log_err(r, "error sending response body");
		return SERVER_ERROR;
	}

	ap_kill_timeout(r);

	log_debug(r, "reading response headers");
	ret = ap_scan_script_header_err_buff(r, f, NULL);
	if (ret) {
		if (ret == SERVER_ERROR) {
			log_err(r, "error reading response headers");
		}
		else {
			/* Work around an Apache bug whereby the returned
			 * status is ignored and status_line is used instead.
			 * This bug is present at least in Apache 1.3.33.
			 */
			r->status_line = NULL;
		}
		ap_bclose(f);
		return ret;
	}

	location = ap_table_get(r->headers_out, "Location");
	if (location && location[0] == '/' &&
		((r->status == HTTP_OK) || ap_is_HTTP_REDIRECT(r->status))) {

		ap_bclose(f);

		/* Internal redirect -- fake-up a pseudo-request */
		r->status = HTTP_OK;

		/* This redirect needs to be a GET no matter what the original
		 * method was.
		 */
		r->method = ap_pstrdup(r->pool, "GET");
		r->method_number = M_GET;

		ap_internal_redirect_handler(location, r);
		return OK;
	}

	/* write headers to client */
	ap_send_http_header(r);

	/* write body to client */
	if (!r->header_only) {
		ap_send_fb(f, r);
	}
	ap_bclose(f);

	return OK;
}

static void scgi_init(server_rec *s, pool *p)
{
    ap_add_version_component("mod_scgi/" MOD_SCGI_VERSION);
}

static void *
create_dir_config(pool *p, char *dirspec)
{
	scgi_cfg *cfg = (scgi_cfg *) ap_pcalloc(p, sizeof(scgi_cfg));

	cfg->enabled = UNSET;
	cfg->mount.addr = UNSET;
	cfg->mount.port = UNSET;

	return (void *) cfg;
}

#define MERGE(b, n, a) (n->a == UNSET ? b->a : n->a)

static void *
merge_dir_config(pool *p, void *basev, void *newv)
{
	scgi_cfg *base, *new;
	scgi_cfg *cfg = (scgi_cfg *) ap_pcalloc(p, sizeof(scgi_cfg));
	base = (scgi_cfg *) basev;
	new = (scgi_cfg *) newv;
	
	cfg->enabled = MERGE(base, new, enabled);
	cfg->mount.addr = MERGE(base, new, mount.addr);
	cfg->mount.port = MERGE(base, new, mount.port);

	return (void *) cfg;
}

static void *
create_server_config(pool *p, server_rec *s)
{
	scgi_server_cfg *c =
		(scgi_server_cfg *) ap_pcalloc(p, sizeof(scgi_server_cfg));

	c->mounts = ap_make_array(p, 20, sizeof(mount_entry));
	return c;
}

static void *
merge_server_config(pool *p, void *basev, void *overridesv)
{
	scgi_server_cfg *c = (scgi_server_cfg *)
		ap_pcalloc(p, sizeof(scgi_server_cfg));
	scgi_server_cfg *base = (scgi_server_cfg *) basev;
	scgi_server_cfg *overrides = (scgi_server_cfg *) overridesv;

	c->mounts = ap_append_arrays(p, overrides->mounts, base->mounts);
	return c;
}


static const char *
cmd_server(cmd_parms *cmd, scgi_cfg *dcfg, char *addr, char *port)
{
	int n;
	char *tmp;

	if (cmd->path == NULL) { /* server command */
		return "not a server command";
	} 

	if ((dcfg->mount.addr = inet_addr(addr)) == INADDR_NONE)
		return "Invalid syntax for server address";

	n = strtol(port, &tmp, 0);
	if (tmp[0] != 0 || n < 0 || n > 65535)
		return "Invalid server port";
	dcfg->mount.port = htons((unsigned short) n);

	return NULL;
}


static const char *
cmd_handler(cmd_parms *cmd, scgi_cfg *dcfg, int flag)
{
	if (cmd->path == NULL) { /* server command */
		return "not a server command";
	} 

	if (flag) {
		dcfg->enabled = ENABLED;
	}
	else {
		dcfg->enabled = DISABLED;
	}

	return NULL;
}

static const char *
cmd_mount(cmd_parms *cmd, void *dummy, char *path, char *addr)
{
	int n;
	char *colon;
	char *addr2;
	char *tmp;

	scgi_server_cfg *scfg = our_sconfig(cmd->server);
	mount_entry *new = ap_push_array(scfg->mounts);
	n = strlen(path);
	while (n > 0 && path[n-1] == '/') {
		n--; /* strip trailing slashes */
	}
	new->path = ap_pstrndup(cmd->pool, path, n);
	if ((colon = strchr(addr, ':')) == NULL)
		return "Invalid syntax for server address";
	addr2 = ap_pstrndup(cmd->pool, addr, colon - addr);
	if ((new->addr = inet_addr(addr2)) == INADDR_NONE)
		return "Invalid syntax for server address";
	n = strtol(colon + 1, &tmp, 0);
	if (tmp[0] != 0 || n < 0 || n > 65535)
		return "Invalid server port";
	new->port = htons((unsigned short) n);
	return NULL;
}

static const command_rec scgi_cmds[] =
{
    { "SCGIServer", cmd_server, NULL, ACCESS_CONF, TAKE2,
      "address and port of an SCGI server (e.g. 127.0.0.1 4000)"},
    { "SCGIHandler", cmd_handler, NULL, ACCESS_CONF, FLAG,
      "On or Off to enable or disable the SCGI handler"},
    { "SCGIMount", cmd_mount, NULL, RSRC_CONF, TAKE2,
      "path prefix and address of SCGI server"},
    {NULL}
};

static const handler_rec scgi_handlers[] =
{
    {"scgi-handler", scgi_handler},
    {NULL}
};

module scgi_module =
{
	STANDARD_MODULE_STUFF,
	scgi_init,			/* module initializer */
	create_dir_config,		/* per-directory config creator */
	merge_dir_config,		/* dir config merger */
	create_server_config,		/* server config creator */
	merge_server_config,		/* server config merger */
	scgi_cmds,			/* command table */
	scgi_handlers,			/* [7] list of handlers */
	scgi_trans,			/* [2] filename-to-URI translation */
	NULL,				/* [5] check/validate user_id */
	NULL,				/* [6] check user_id is valid *here* */
	NULL,				/* [4] check access by host address */
	NULL,				/* [7] MIME type checker/setter */
	NULL,				/* [8] fixups */
	NULL,				/* [10] logger */
#if MODULE_MAGIC_NUMBER >= 19970103
	NULL,				/* [3] header parser */
#endif
#if MODULE_MAGIC_NUMBER >= 19970719
	NULL,				/* process initializer */
#endif
#if MODULE_MAGIC_NUMBER >= 19970728
	NULL,				/* process exit/cleanup */
#endif
#if MODULE_MAGIC_NUMBER >= 19970902
	NULL				/* [1] post read_request handling */
#endif
};
