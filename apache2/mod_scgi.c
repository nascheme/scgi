/* mod_scgi.c
 *
 * Apache 2 implementation of the SCGI protocol.
 *
 */

#define MOD_SCGI_VERSION "2.2"
#define SCGI_PROTOCOL_VERSION "1"

#include "ap_config.h"
#include "apr_version.h"
#include "apr_lib.h"
#include "apr_strings.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_request.h"
#include "http_log.h"
#include "http_protocol.h"
#include "util_script.h"

#define DEFAULT_TIMEOUT  60 /* default socket timeout */

#define UNSET 0
#define ENABLED 1
#define DISABLED 2

#if APR_MAJOR_VERSION == 0
#define apr_socket_send apr_send
#define GET_PORT(port, addr) apr_sockaddr_port_get(&(port), addr)
#define CREATE_SOCKET(sock, family, pool) \
	    apr_socket_create(sock, family, SOCK_STREAM, pool)
#else
#define GET_PORT(port, addr) ((port) = (addr)->port)
#define CREATE_SOCKET(sock, family, pool) \
	    apr_socket_create(sock, family, SOCK_STREAM, APR_PROTO_TCP, pool)
#endif

typedef struct {
    char *path;
    char *addr;
    apr_port_t port;
} mount_entry;

/*
 * Configuration record.  Used per-directory configuration data.
 */
typedef struct {
    mount_entry mount;
    int enabled; /* mod_scgi is enabled from this directory */
    int timeout;
} scgi_cfg;

/* Server level configuration */
typedef struct {
    apr_array_header_t *mounts;
    int timeout;
} scgi_server_cfg;

/*
 * Declare ourselves so the configuration routines can find and know us.
 * We'll fill it in at the end of the module.
 */
module AP_MODULE_DECLARE_DATA scgi_module;

/*
 * Locate our directory configuration record for the current request.
 */
static scgi_cfg *
our_dconfig(request_rec *r)
{
    return (scgi_cfg *) ap_get_module_config(r->per_dir_config, &scgi_module);
}

static scgi_server_cfg *our_sconfig(server_rec *s)
{
    return (scgi_server_cfg *) ap_get_module_config(s->module_config,
                                                    &scgi_module);
}

static int
mount_entry_matches(const char *url, const char *prefix,
                    const char **path_info)
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

static int scgi_translate(request_rec *r)
{
    scgi_cfg *cfg = our_dconfig(r);

    if (cfg->enabled == DISABLED) {
        return DECLINED;
    }

    if (cfg->mount.addr != UNSET) {
        ap_assert(cfg->mount.port != UNSET);
        r->handler = "scgi-handler";
        r->filename = r->uri;
        return OK;
    }
    else {
        int i;
        scgi_server_cfg *scfg = our_sconfig(r->server);
        mount_entry *entries = (mount_entry *) scfg->mounts->elts;
        for (i = 0; i < scfg->mounts->nelts; ++i) {
            const char *path_info;
            mount_entry *mount = &entries[i];
            if (mount_entry_matches(r->uri, mount->path, &path_info)) {
                r->handler = "scgi-handler";
                r->path_info = apr_pstrdup(r->pool, path_info);
                r->filename = r->uri;
                ap_set_module_config(r->request_config, &scgi_module, mount);
                return OK;
            }
        }
    }
    return DECLINED;
}

static int scgi_map_location(request_rec *r)
{
    if (r->handler && strcmp(r->handler, "scgi-handler") == 0) {
        return OK; /* We don't want directory walk. */
    }
    return DECLINED;
}

static void log_err(const char *file, int line, int index, request_rec *r,
                    apr_status_t status, const char *msg)
{
    ap_log_rerror(file, line, index, APLOG_ERR, status, r, "scgi: %s", msg);
}

static void log_debug(const char *file, int line, int index, request_rec *r, const
                      char *msg)
{
    ap_log_rerror(file, line, index, APLOG_DEBUG, APR_SUCCESS, r, "%s", msg);
}

static char *http2env(apr_pool_t *p, const char *name)
{
    char *env_name = apr_pstrcat(p, "HTTP_", name, NULL);
    char *cp;
    
    for (cp = env_name + 5; *cp != 0; cp++) {
        if (*cp == '-') {
            *cp = '_';
        }
        else {
            *cp = apr_toupper(*cp);
        }
    }

    return env_name;
}

static char *lookup_name(apr_table_t *t, const char *name)
{
    const apr_array_header_t *hdrs_arr = apr_table_elts(t);
    apr_table_entry_t *hdrs = (apr_table_entry_t *) hdrs_arr->elts;
    int i;

    for (i = 0; i < hdrs_arr->nelts; ++i) {
        if (hdrs[i].key == NULL)
            continue;

        if (strcasecmp(hdrs[i].key, name) == 0)
            return hdrs[i].val;
    }
    return NULL;
}


static char *lookup_header(request_rec *r, const char *name)
{
    return lookup_name(r->headers_in, name);
}


static void add_header(apr_table_t *t, const char *name, const char *value)
{
    if (name != NULL && value != NULL)
        apr_table_addn(t, name, value);
}

static int find_path_info(const char *uri, const char *path_info)
{
    int n;
    n = strlen(uri) - strlen(path_info);
    ap_assert(n >= 0);
    return n;
}

/* This code is a duplicate of what's in util_script.c.  We can't use
 * r->unparsed_uri because it gets changed if there was a redirect. */
static char *original_uri(request_rec *r)
{
    char *first, *last;

    if (r->the_request == NULL) {
	return (char *) apr_pcalloc(r->pool, 1);
    }

    first = r->the_request;	/* use the request-line */

    while (*first && !apr_isspace(*first)) {
	++first;		/* skip over the method */
    }
    while (apr_isspace(*first)) {
	++first;		/*   and the space(s)   */
    }

    last = first;
    while (*last && !apr_isspace(*last)) {
	++last;			/* end at next whitespace */
    }

    return apr_pstrmemdup(r->pool, first, last - first);
}

/* buffered socket implementation (buckets are overkill) */

#define BUFFER_SIZE 8000

struct sockbuff {
    apr_socket_t *sock;
    char buf[BUFFER_SIZE];
    int used;
};

static void binit(struct sockbuff *s, apr_socket_t *sock)
{
    s->sock = sock;
    s->used = 0;
}

static apr_status_t sendall(apr_socket_t *sock, char *buf, apr_size_t len)
{
    apr_status_t rv;
    apr_size_t n;
    while (len > 0) {
        n = len;
        if ((rv = apr_socket_send(sock, buf, &n))) return rv;
        buf += n;
        len -= n;
    }
    return APR_SUCCESS;
}

static apr_status_t bflush(struct sockbuff *s)
{
    apr_status_t rv;
    ap_assert(s->used >= 0 && s->used <= BUFFER_SIZE);
    if (s->used) {
            if ((rv = sendall(s->sock, s->buf, s->used))) return rv;
            s->used = 0;
    }
    return APR_SUCCESS;
}

static apr_status_t bwrite(struct sockbuff *s, char *buf, apr_size_t len)
{
    apr_status_t rv;
    if (len >= BUFFER_SIZE - s->used) {
        if ((rv = bflush(s))) return rv;
        while (len >= BUFFER_SIZE) {
            if ((rv = sendall(s->sock, buf, BUFFER_SIZE))) return rv;
            buf += BUFFER_SIZE;
            len -= BUFFER_SIZE;
        }
    }
    if (len > 0) {
        ap_assert(len < BUFFER_SIZE - s->used);
        memcpy(s->buf + s->used, buf, len);
        s->used += len;
    }
    return APR_SUCCESS;
}

static apr_status_t bputs(struct sockbuff *s, char *buf)
{
    return bwrite(s, buf, strlen(buf));
}

static apr_status_t bputc(struct sockbuff *s, char c)
{
    char buf[1];
    buf[0] = c;
    return bwrite(s, buf, 1);
}


static apr_status_t
send_headers(request_rec *r, struct sockbuff *s)
{
    /* headers to send */
    apr_table_t *t;
    const apr_array_header_t *hdrs_arr, *env_arr;
    apr_table_entry_t *hdrs, *env;
    unsigned long int n = 0;
    char *buf;
    int i;
    apr_status_t rv = 0;
    apr_port_t  port = 0;
    GET_PORT(port, r->useragent_addr);

    log_debug(APLOG_MARK,r, "sending headers");
    t = apr_table_make(r->pool, 40);
    if (!t)
	    return APR_ENOMEM;
    /* CONTENT_LENGTH must come first and always be present */
    buf = lookup_header(r, "Content-Length");
    if (buf == NULL)
	    buf = "0";
    add_header(t, "CONTENT_LENGTH",  buf);
    add_header(t, "SCGI", SCGI_PROTOCOL_VERSION);
    add_header(t, "SERVER_SOFTWARE", ap_get_server_banner());
    add_header(t, "SERVER_PROTOCOL", r->protocol);
    add_header(t, "SERVER_NAME", ap_get_server_name(r));
    add_header(t, "SERVER_ADMIN", r->server->server_admin);
    add_header(t, "SERVER_ADDR", r->connection->local_ip);
    add_header(t, "SERVER_PORT", apr_psprintf(r->pool, "%u",
                                              ap_get_server_port(r)));
    add_header(t, "REMOTE_ADDR", r->useragent_ip);
    add_header(t, "REMOTE_PORT", apr_psprintf(r->pool, "%d", port));
    add_header(t, "REMOTE_USER", r->user);
    add_header(t, "REQUEST_METHOD", r->method);
    add_header(t, "REQUEST_URI", original_uri(r));
    add_header(t, "QUERY_STRING", r->args ? r->args : "");
    if (r->path_info) {
        int path_info_start = find_path_info(r->uri, r->path_info);
        add_header(t, "SCRIPT_NAME", apr_pstrndup(r->pool, r->uri,
                                                  path_info_start));
        add_header(t, "PATH_INFO", r->path_info);
    }
    else {
        /* skip PATH_INFO, don't know it */
        add_header(t, "SCRIPT_NAME", r->uri);
    }
    add_header(t, "CONTENT_TYPE", lookup_header(r, "Content-type"));
    add_header(t, "DOCUMENT_ROOT", ap_document_root(r));

    /* HTTP headers */
    hdrs_arr = apr_table_elts(r->headers_in);
    hdrs = (apr_table_entry_t *) hdrs_arr->elts;
    for (i = 0; i < hdrs_arr->nelts; ++i) {
        if (hdrs[i].key) {
            add_header(t, http2env(r->pool, hdrs[i].key), hdrs[i].val);
        }
    }

    /* environment variables */
    env_arr = apr_table_elts(r->subprocess_env);
    env = (apr_table_entry_t*) env_arr->elts;
    for (i = 0; i < env_arr->nelts; ++i) {
        add_header(t, env[i].key, env[i].val);
    }

    hdrs_arr = apr_table_elts(t);
    hdrs = (apr_table_entry_t*) hdrs_arr->elts;

    /* calculate length of header data (including nulls) */
    for (i = 0; i < hdrs_arr->nelts; ++i) {
        n += strlen(hdrs[i].key) + 1;
        n += strlen(hdrs[i].val) + 1;
    }

    buf = apr_psprintf(r->pool, "%lu:", n);
    if (!buf)
        return APR_ENOMEM;
    rv = bputs(s, buf);
    if (rv)
        return rv;

    for (i = 0; i < hdrs_arr->nelts; ++i) {
        rv = bputs(s, hdrs[i].key);
        if (rv) return rv;
        rv = bputc(s, '\0');
        if (rv) return rv;
        rv = bputs(s, hdrs[i].val);
        if (rv) return rv;
        rv = bputc(s, '\0');
        if (rv) return rv;
    }

    rv = bputc(s, ',');
    if (rv)
        return rv;

    return APR_SUCCESS;
}

static apr_status_t send_request_body(request_rec *r, struct sockbuff *s)
{
    if (ap_should_client_block(r)) {
        char buf[BUFFER_SIZE];
        apr_status_t rv;
        apr_off_t len;

        while ((len = ap_get_client_block(r, buf, sizeof buf)) > 0) {
            if ((rv = bwrite(s, buf, len))) return rv;
        }
        if (len == -1)
            return HTTP_INTERNAL_SERVER_ERROR; /* what to return? */
    }
    return APR_SUCCESS;
}

#define CONFIG_VALUE(value, fallback) ((value) != UNSET ? (value) : (fallback))

static apr_status_t
open_socket(apr_socket_t **sock, request_rec *r)
{
    int timeout;
    int retries = 4;
    int sleeptime = 1;
    apr_status_t rv;
    apr_sockaddr_t *sockaddr;
    scgi_server_cfg *scfg = our_sconfig(r->server);
    scgi_cfg *cfg = our_dconfig(r);
    mount_entry *m = (mount_entry *) ap_get_module_config(r->request_config,
                                                          &scgi_module);
    if (!m) {
	m = &cfg->mount;
    }

    timeout = CONFIG_VALUE(cfg->timeout, CONFIG_VALUE(scfg->timeout,
                                                      DEFAULT_TIMEOUT));
    rv = apr_sockaddr_info_get(&sockaddr,
                               CONFIG_VALUE(m->addr, "localhost"),
                               APR_UNSPEC,
                               CONFIG_VALUE(m->port, 4000),
                               0,
                               r->pool);
    if (rv) {
        log_err(APLOG_MARK, r, rv, "apr_sockaddr_info_get() error");
        return rv;
    }

 restart:
    *sock = NULL;
    rv = CREATE_SOCKET(sock, sockaddr->family, r->pool);
    if (rv) {
        log_err(APLOG_MARK, r, rv, "apr_socket_create() error");
        return rv;
    }

    rv = apr_socket_timeout_set(*sock, apr_time_from_sec(timeout));
    if (rv) {
        log_err(APLOG_MARK, r, rv, "apr_socket_timeout_set() error");
        return rv;
    }

    rv = apr_socket_connect(*sock, sockaddr);
    if (rv) {
	apr_socket_close(*sock);
        if ((APR_STATUS_IS_ECONNREFUSED(rv) |
	     APR_STATUS_IS_EINPROGRESS(rv)) && retries > 0) {
            /* server may be temporarily down, retry */
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, rv, r,
                          "scgi: connection failed, retrying");
            apr_sleep(apr_time_from_sec(sleeptime));
            --retries;
            sleeptime *= 2;
            goto restart;
        }
        log_err(APLOG_MARK, r, rv, "scgi: can't connect to server");
        return rv;
    }

#ifdef APR_TCP_NODELAY
    /* disable Nagle, we don't send small packets */
    apr_socket_opt_set(*sock, APR_TCP_NODELAY, 1);
#endif

    return APR_SUCCESS;
}

static int scgi_handler(request_rec *r)
{
    apr_status_t rv = 0;
    int http_status = 0;
    struct sockbuff s;
    apr_socket_t *sock;
    apr_bucket_brigade *bb = NULL;
    apr_bucket *b          = NULL;
    const char *location;

    if (strcmp(r->handler, "scgi-handler"))
        return DECLINED;

    http_status = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR);
    if (http_status != OK)
        return http_status;

    log_debug(APLOG_MARK, r, "connecting to server");

    rv = open_socket(&sock, r);
    if (rv) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    binit(&s, sock);

    rv = send_headers(r, &s);
    if (rv) {
        log_err(APLOG_MARK, r, rv, "error sending request headers");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    rv = send_request_body(r, &s);
    if (rv) {
        log_err(APLOG_MARK, r, rv, "error sending request body");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    rv = bflush(&s);
    if (rv) {
        log_err(APLOG_MARK, r, rv, "error sending request");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    log_debug(APLOG_MARK, r, "reading response headers");
    bb = apr_brigade_create(r->connection->pool, r->connection->bucket_alloc);
    b = apr_bucket_socket_create(sock, r->connection->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, b);
    b = apr_bucket_eos_create(r->connection->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, b);

    rv = ap_scan_script_header_err_brigade(r, bb, NULL);
    if (rv) {
        if (rv != HTTP_INTERNAL_SERVER_ERROR) {
            /* Work around an Apache bug whereby the returned status is
             * ignored and status_line is used instead.  This bug is
             * present at least in 2.0.54.
             */
            r->status_line = NULL;
        }
        apr_brigade_destroy(bb);
        return rv;
    }

    location = apr_table_get(r->headers_out, "Location");

    if (location && location[0] == '/' &&
        ((r->status == HTTP_OK) || ap_is_HTTP_REDIRECT(r->status))) {

        apr_brigade_destroy(bb);

        /* Internal redirect -- fake-up a pseudo-request */
        r->status = HTTP_OK;

        /* This redirect needs to be a GET no matter what the original
         * method was.
         */
        r->method = apr_pstrdup(r->pool, "GET");
        r->method_number = M_GET;

        ap_internal_redirect_handler(location, r);
        return OK;
    }

    rv = ap_pass_brigade(r->output_filters, bb);
    if (rv) {
	/* It's possible that the client closed the connection before
           the transfer was complete. If so, don't return an error. */
        if (r->connection->aborted) {
            log_err(APLOG_MARK, r, rv, "sending response (error ignored)");
	}
	else {
            log_err(APLOG_MARK, r, rv, "ap_pass_brigade()");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    return OK;
}


static int scgi_init(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp,
                       server_rec *base_server)
{
    ap_add_version_component(p, "mod_scgi/" MOD_SCGI_VERSION);
    return OK;
}


static void *
create_dir_config(apr_pool_t *p, char *dirspec)
{
    scgi_cfg *cfg = apr_pcalloc(p, sizeof(scgi_cfg));

    cfg->enabled = UNSET;
    cfg->mount.addr = UNSET;
    cfg->mount.port = UNSET;
    cfg->timeout = UNSET;

    return cfg;
}

#define MERGE(b, n, a) (n->a == UNSET ? b->a : n->a)

static void *
merge_dir_config(apr_pool_t *p, void *basev, void *newv)
{
    scgi_cfg* cfg = apr_pcalloc(p, sizeof(scgi_cfg));
    scgi_cfg* base = basev;
    scgi_cfg* new = newv;

    cfg->enabled = MERGE(base, new, enabled);
    cfg->mount.addr = MERGE(base, new, mount.addr);
    cfg->mount.port = MERGE(base, new, mount.port);
    cfg->timeout = MERGE(base, new, timeout);

    return cfg;
}

static void *
create_server_config(apr_pool_t *p, server_rec *s)
{
	scgi_server_cfg *c =
		(scgi_server_cfg *) apr_pcalloc(p, sizeof(scgi_server_cfg));

	c->mounts = apr_array_make(p, 20, sizeof(mount_entry));
        c->timeout = UNSET;
	return c;
}

static void *
merge_server_config(apr_pool_t *p, void *basev, void *overridesv)
{
	scgi_server_cfg *c = (scgi_server_cfg *)
		apr_pcalloc(p, sizeof(scgi_server_cfg));
	scgi_server_cfg *base = (scgi_server_cfg *) basev;
	scgi_server_cfg *overrides = (scgi_server_cfg *) overridesv;

	c->mounts = apr_array_append(p, overrides->mounts, base->mounts);
        c->timeout = MERGE(base, overrides, timeout);
	return c;
}

static const char *
cmd_mount(cmd_parms *cmd, void *dummy, const char *path, const char *addr)
{
    int n;
    apr_status_t rv;
    char *scope_id = NULL; /* A ip6 parameter - not used here. */
    scgi_server_cfg *scfg = our_sconfig(cmd->server);
    mount_entry *new = apr_array_push(scfg->mounts);
    n = strlen(path);
    while (n > 0 && path[n-1] == '/') {
        n--; /* strip trailing slashes */
    }
    new->path = apr_pstrndup(cmd->pool, path, n);
    rv = apr_parse_addr_port(&new->addr, &scope_id, &new->port, addr,
                             cmd->pool);
    if (rv)
        return "error parsing address:port string";
    return NULL;
}

static const char *
cmd_server(cmd_parms *cmd, void *pcfg, const char *addr_and_port)
{
    apr_status_t rv;
    scgi_cfg *cfg = pcfg;
    char *scope_id = NULL; /* A ip6 parameter - not used here. */

    if (cmd->path == NULL)
        return "not a server command";

    rv = apr_parse_addr_port(&cfg->mount.addr, &scope_id, &cfg->mount.port,
                             addr_and_port, cmd->pool);
    if (rv)
        return "error parsing address:port string";

    return NULL;
}


static const char *
cmd_handler(cmd_parms* cmd, void* pcfg, int flag)
{
    scgi_cfg *cfg = pcfg;

    if (cmd->path == NULL) /* server command */
        return "not a server command";

    if (flag)
        cfg->enabled = ENABLED;
    else
        cfg->enabled = DISABLED;

    return NULL;
}


static const char *
cmd_timeout(cmd_parms *cmd, void* pcfg, const char *strtimeout)
{
    scgi_cfg *dcfg = pcfg;
    int timeout = atoi(strtimeout);

    if (cmd->path == NULL) {
        scgi_server_cfg *scfg = our_sconfig(cmd->server);
        scfg->timeout = timeout;
    }
    else {
        dcfg->timeout = timeout;
    }

    return NULL;
}

static const command_rec scgi_cmds[] =
{
    AP_INIT_TAKE2("SCGIMount", cmd_mount, NULL, RSRC_CONF,
                  "path prefix and address of SCGI server"),
    AP_INIT_TAKE1("SCGIServer", cmd_server, NULL, ACCESS_CONF,
                  "Address and port of an SCGI server (e.g. localhost:4000)"),
    AP_INIT_FLAG( "SCGIHandler", cmd_handler, NULL, ACCESS_CONF,
                  "On or Off to enable or disable the SCGI handler"),
    AP_INIT_TAKE1("SCGIServerTimeout", cmd_timeout, NULL, ACCESS_CONF|RSRC_CONF,
                  "Timeout (in seconds) for communication with the SCGI server."),
    {NULL}
};


static void scgi_register_hooks(apr_pool_t *p)
{
    ap_hook_post_config(scgi_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler(scgi_handler, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_translate_name(scgi_translate, NULL, NULL, APR_HOOK_LAST);
    ap_hook_map_to_storage(scgi_map_location, NULL, NULL, APR_HOOK_FIRST);
}


/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA scgi_module = {
    STANDARD20_MODULE_STUFF,
    create_dir_config,             /* create per-dir config structs */
    merge_dir_config,              /* merge per-dir config structs */
    create_server_config,          /* create per-server config structs */
    merge_server_config,           /* merge per-server config structs */
    scgi_cmds,                     /* table of config file commands */
    scgi_register_hooks,           /* register hooks */
};
