#!/usr/bin/env python3
"""A pre-forking HTTP server that runs ASGI applications.

Example usage:

    python3 -m scgi.asgi_server myapi:main --init=myapp:init --direct

The "myapi.main" will be imported and used as the ASGI callable.  The --init
argument is optional.  If provided, it will be called and run before any
requests are sent to the application.

Note: this server implements only a bare minimum of the HTTP 1/1 protocol.  It
should not be used in "the wild" as a public facing HTTP server.  Instead, run
it behind something like HAProxy and use the PROXY protocol.
"""
import sys
import pprint
import os
from typing import Optional, Callable
import re
import io
import time
from attrs import define
import secrets
import socket
import tempfile
import traceback
import urllib.parse
import http.client
import trio
from scgi import session_server, passfd
from scgi.util import HEADER_ENCODING


DEBUG = False

DEBUG_ENV = False

DEBUG_HEADERS = False

# Allow connections without PROXY protocol or X-Real-IP
ALLOW_DIRECT = False


def log(*args):
    print(*args, flush=True)


def log_traceback():
    log(traceback.format_exc())


def log_request(req, status_duration, total_duration, total_size):
    remote_ip = req.env.get('REMOTE_ADDR')
    uri = req.env.get('REQUEST_URI')
    method = req.env.get('REQUEST_METHOD')
    body_size = req.env.get('HTTP_CONTENT_LENGTH') or 0
    req.log(
        remote_ip,
        method,
        uri,
        req.response_status,
        total_size,
        body_size,
        f'{status_duration:.3f}s',
        f'{total_duration:.3f}s',
    )


def debug(*args):
    if DEBUG:
        print(*args, file=sys.stderr)


# buffer size for socket reads/writes
BUF_SMALL = 1 << 12  # 4 KiB
BUF_LARGE = 1 << 23  # 8 MiB

# maximum size for HTTP headers
HEADER_MAX_SIZE = 8000


def _is_https(env):
    return (
        env.get('HTTPS', 'off').lower() in ('on', 'yes', '1')
        or env.get('SERVER_PORT_SECURE', '0') != '0'
    )


def _get_int(env, name):
    v = env.get(name) or ''
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


class Request:
    def __init__(self, env, headers):
        # unique identifier for request, for logging.  This is not absolutely
        # assured to be unique but is extremely likely to be so.
        self.request_id = secrets.token_hex(4)
        self.env = env
        self.headers = headers
        self.response_status = None
        self.debug('headers', len(headers))

    def debug(self, *args):
        debug(self.request_id, *args)

    def log(self, *args):
        log(self.request_id, *args)


class ProtocolError(Exception):
    pass


def parse_env(conn, host_name, host_port, headers):
    split_newlines = re.compile(r'\r?\n').split
    lines = split_newlines(headers.decode('latin1'))
    first_line = lines[0] if lines else ''
    need_real_ip = False
    if not ALLOW_DIRECT:
        if first_line.startswith('PROXY '):
            # HAProxy proxy protocol, see:
            # http://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
            # Example line:
            #     PROXY TCP4 192.168.0.1 192.168.0.11 56324 443\r\n
            parts = first_line.split()
            del lines[0]
            remote_host = parts[2]
            remote_port = parts[4]
            host_name = parts[3]
            host_port = parts[5]
        else:
            need_real_ip = True  # will check later
    else:
        # In this case, we are running without a front-end web server.  The
        # clients connect directly to this server.  Generally this is only
        # used for dev work or for testing.  By default, ALLOW_DIRECT is
        # not set.
        peer = conn.socket.getpeername()
        if isinstance(peer, tuple) and len(peer) == 2:
            remote_host, remote_port = peer
        else:
            remote_host = 'unknown'
            remote_port = 0
    fp = io.BytesIO('\r\n'.join(lines[1:]).encode('latin1'))
    headers = http.client.parse_headers(fp)
    if need_real_ip:
        # The ALLOW_DIRECT option is turned off.  In this case, we want
        # to see a "PROXY" header or the front-end web server must set the
        # X-Real-IP header.  If not, it is an error because we would be using
        # the wrong IP for the client.
        remote_host = headers.get('x-real-ip')
        remote_port = headers.get('x-real-port') or 0
        if not remote_host:
            raise ProtocolError('missing X-Real-IP header')
    parts = lines[0].strip().split()
    if len(parts) != 3:
        debug(
            f'{remote_host:remote_port} invalid request line', repr(lines[0])
        )
        raise ProtocolError('invalid request line')
    method, uri, version = parts
    path, _, qs = uri.partition('?')
    env = {
        'CONTENT_LENGTH': '0',
        'SCGI': '1',
        'REQUEST_METHOD': method,
        'SCRIPT_NAME': '',
        'PATH_INFO': urllib.parse.unquote(path),
        'QUERY_STRING': qs,
        'REQUEST_URI': uri,
        'SERVER_PROTOCOL': version,
        'SERVER_SOFTWARE': 'asgi_server/1.0',
        'SERVER_NAME': host_name,
        'SERVER_PORT': host_port,
        'REMOTE_PORT': str(remote_port),
        'REMOTE_ADDR': remote_host,
        'HTTPS': headers.get('x-https') or 'off',
    }
    if headers.get('content-type') is None:
        env['CONTENT_TYPE'] = headers.get_content_type()
    else:
        env['CONTENT_TYPE'] = headers['content-type']
    length = headers.get('content-length')
    if length:
        env['CONTENT_LENGTH'] = length
    for name in headers.keys():
        if '_' in name:
            # ignore, prevents header smuggling
            continue
        values = headers.get_all(name)
        value = ','.join(values)
        name = name.replace('-', '_').upper()
        if name not in env:
            env['HTTP_' + name] = value.strip()
    if DEBUG_ENV:
        debug('request env:')
        pprint.pprint(env)
    if DEBUG_HEADERS:
        debug('request headers:')
        pprint.pprint(dict(headers))
    return env


def _h_enc(s):
    """Encode header text as bytes."""
    return s.encode(HEADER_ENCODING)


class RequestHandler:
    """Handle a single HTTP request."""

    def __init__(self, app):
        self.app = app
        self.total_size = 0
        self._started = False
        self._response_complete = False

    async def _write_response_header(self, conn, status, headers):
        status_line = f'HTTP/1.1 {status}\r\n'
        await conn.send_all(_h_enc(status_line))
        for name, value in headers:
            header = f'{name}: {value}\r\n'
            await conn.send_all(_h_enc(header))
        await conn.send_all(b'\r\n')

    async def produce(self, conn, req, req_file):
        env = req.env
        if _is_https(env):
            scheme = 'https'
        else:
            scheme = 'http'

        client = (env.get('REMOTE_ADDR') or '', _get_int(env, 'REMOTE_PORT'))
        server = (env.get('SERVER_NAME') or '', _get_int(env, 'SERVER_PORT'))
        # url = urllib.parse.urlparse(env.get('REQUEST_URI'))
        headers = []
        if 'PATH_INFO' in env:
            path = env['PATH_INFO']
            raw_path = _h_enc(path)
            path = urllib.parse.unquote(path)
        else:
            path = ''
            raw_path = None
        if 'QUERY_STRING' in env:
            query_string = _h_enc(env['QUERY_STRING'])
        else:
            query_string = b''
        content_length = env.get('CONTENT_LENGTH')
        if content_length:
            headers.append(
                (b'content-length', _h_enc(content_length)),
            )
        request_body = req_file.read()
        scope = {
            'asgi': {'spec_version': '2.3', 'version': '3.0'},
            'type': 'http',
            'client': client,
            'server': server,
            'headers': headers,
            'http_version': '1.1',
            'method': env.get('REQUEST_METHOD') or 'GET',
            'path': path,
            'query_string': query_string,
            'raw_path': raw_path,
            'root_path': env.get('SCRIPT_NAME') or '',
            'body': request_body,
            'scheme': scheme,
            'state': {},
        }
        if DEBUG:
            debug('request headers:')
        for k, v in env.items():
            debug(f'  {k}={v}')
            if not k.startswith('HTTP_'):
                continue
            k = k[5:].replace('_', '-').lower()
            headers.append(
                (k.encode(HEADER_ENCODING), v.encode(HEADER_ENCODING))
            )

        if DEBUG:
            pprint.pprint(scope)

        message_event = trio.Event()

        def gen_receive_events():
            # Events to send to the application.  For SCGI there is only
            # one request per connection so close after handling it.
            while True:
                if not self._started:
                    self._started = True
                    if request_body:
                        yield {
                            'type': 'http.request',
                            'body': request_body,
                            'more_body': False,
                        }
                    else:
                        yield {'type': 'http.request'}
                elif self._response_complete:
                    yield {'type': 'http.disconnect'}
                else:
                    yield None

        receive_events = gen_receive_events()

        async def receive():
            event = next(receive_events)
            debug('send event', event)
            if event is None:
                await message_event.wait()
                return {'type': 'http.disconnect'}
            else:
                return event

        async def send(event):
            # Handle events from the application.
            debug('got event', event)
            if event['type'] == 'http.response.start':
                await self._write_response_header(
                    conn, event['status'], event.get('headers') or []
                )
            elif event['type'] == 'http.response.body':
                body = event['body']
                self.total_size += len(body)
                await conn.send_all(body)
                if not event.get('more_body'):
                    self._response_complete = True
                    message_event.set()
            else:
                debug('ignore unknown event')

        await self.app(scope, receive, send)


class AppHandler:
    """Handler for processing incoming HTTP requests.   This gets created
    once per each worker (child) process.  The handle_connection() method gets
    called each time there is a request to handle.
    """

    def __init__(self, parent_fd, host, port, app):
        self.parent_fd = parent_fd
        self.app = app
        self.host = host
        self.port = port
        self.host_name = socket.getfqdn(self.host)

    def serve(self):
        while True:
            try:
                # indicates that child is ready
                os.write(self.parent_fd, b'1')
                fd = passfd.recvfd(self.parent_fd)
            except (IOError, OSError):
                # parent probably exited (EPIPE comes thru as OSError)
                raise SystemExit
            conn = socket.fromfd(fd, socket.AF_INET, socket.SOCK_STREAM)
            # Make sure the socket is blocking.  Apparently, on FreeBSD the
            # socket is non-blocking.  I think that's an OS bug but I don't
            # have the resources to track it down.
            conn.setblocking(1)
            os.close(fd)
            try:
                self.handle_connection(conn)
            finally:
                try:
                    conn.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                conn.close()

    async def read_env(self, conn):
        # read HTTP request headers
        buf = b''
        sep = re.compile(b'\r?\n\r?\n')  # separator of headers from body
        while True:
            chunk = await conn.receive_some(BUF_SMALL)
            if not chunk:
                # an empty string from receive_some() indicates end-of-stream
                raise ProtocolError('end of stream while reading env')
            buf += chunk
            if sep.search(buf):
                break  # we read enough to get headers
            if len(buf) >= HEADER_MAX_SIZE:
                # prevent DoS attacks.  Various web servers set limits on
                # headers sizes, typically 8 kB.
                raise ProtocolError('HTTP headers too large')
        headers, buf = sep.split(buf, 1)
        env = parse_env(conn, self.host_name, self.port, headers)
        req = Request(env, headers)
        return req, buf

    async def handle_async(self, conn):
        t0 = time.time()
        req, buf = await self.read_env(conn)
        content_length = int(req.env.get('CONTENT_LENGTH') or 0)

        # read request
        req_file = tempfile.SpooledTemporaryFile(max_size=500_000)
        n = len(buf)
        req_file.write(buf)
        while n < content_length:
            buf = await conn.receive_some(BUF_LARGE)
            if not buf:
                # an empty string from receive_some() indicates end-of-stream
                raise ProtocolError('end of stream while reading response')
            n += len(buf)
            req_file.write(buf)
        req.debug('request body size', req_file.tell())
        req_file.seek(0)

        handler = RequestHandler(self.app)
        t1 = time.time()
        await handler.produce(conn, req, req_file)

        req_file.close()
        t2 = time.time()

        log_request(req, t1 - t0, t2 - t0, handler.total_size)

    def handle_connection(self, conn):
        """Handle an incoming request."""
        sock = trio.socket.from_stdlib_socket(conn)
        stream = trio.SocketStream(sock)
        trio.run(self.handle_async, stream)


def _get_app(app_spec: str) -> Callable:
    """Lookup application object for ASGI.  This will be called according
    the the ASGI protocol."""
    mod_name, sep, app_name = app_spec.partition(':')
    if not sep:
        raise SystemExit('Invalid "app" argument, missing colon.')
    module = __import__(mod_name)
    app = getattr(module, app_name)
    return app


def _get_app_init(init_spec: str) -> Optional[Callable]:
    """Lookup the application initalize function.  This is called in the
    child process, after the fork.  It is called once at startup of the
    process.
    """
    # FIXME: this should probably use a "lifespan.startup" event rather
    # this this function call.  This approach is simpler to implement.
    if init_spec:
        init_mod_name, sep, init_name = init_spec.partition(':')
        init_mod = __import__(init_mod_name)
        init_func = getattr(init_mod, init_name)
    else:
        init_func = None
    return init_func


DEFAULT_HOST = 'localhost'
DEFAULT_PORT = 3000


@define
class ServerArgs:
    app_spec: str
    init_spec: str
    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT


def handler_factory(args: ServerArgs):
    def make_handler(parent_fd):
        app = _get_app(args.app_spec)
        init_func = _get_app_init(args.init_spec)
        if init_func is not None:
            init_func()
        return AppHandler(parent_fd, args.host, args.port, app)

    return make_handler


def run_server(args: ServerArgs):
    print('server running on %s:%s' % (args.host, args.port))
    session_server.SCGIServer(
        handler_class=handler_factory(args),
        host=args.host,
        port=args.port,
    ).serve()


def main():
    global DEBUG, DEBUG_ENV, DEBUG_HEADERS, ALLOW_DIRECT
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--direct',
        default=False,
        action='store_true',
        help='Allow direct connections, without PROXY or X-Real-IP',
    )
    parser.add_argument(
        '--debug',
        '-d',
        default=False,
        action='store_true',
        help='Enable verbose debugging',
    )
    parser.add_argument(
        '--debug-env',
        default=False,
        action='store_true',
        help='Enable debugging of request env',
    )
    parser.add_argument(
        '--debug-headers',
        default=False,
        action='store_true',
        help='Enable debugging of request headers',
    )
    parser.add_argument(
        '--host',
        '-H',
        default=DEFAULT_HOST,
        help='Host address to listen on.',
    )
    parser.add_argument(
        '--port',
        '-p',
        default=DEFAULT_PORT,
        type=int,
        help='TCP port to listen on.',
    )
    parser.add_argument(
        '--init',
        default='',
        help=(
            'Initialize function to call for appliction post-fork, e.g.'
            ' "myapp:init".'
        ),
    )

    parser.add_argument(
        'app', help='Name of module and function to call, e.g. "myapp:main"'
    )
    args = parser.parse_args()
    DEBUG = args.debug
    DEBUG_ENV = args.debug_env
    DEBUG_HEADERS = args.debug_headers
    ALLOW_DIRECT = args.direct

    server_args = ServerArgs(
        app_spec=args.app, init_spec=args.init, host=args.host, port=args.port
    )
    run_server(server_args)


if __name__ == '__main__':
    main()
