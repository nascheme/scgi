import sys
import asyncio
import pprint
import urllib.parse
import os
from scgi import session_server
from scgi.util import HEADER_ENCODING

DEBUG = False


def debug(*args):
    if DEBUG:
        print(*args, file=sys.stderr)


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


class RequestHandler:
    """Handle a single HTTP request."""

    def __init__(self, app):
        self.app = app
        self._started = False
        self._response_complete = False

    def _write_response_header(self, output, status, headers):
        def w(name, value):
            header = f'{name}: {value}\r\n'
            output.write(header.encode(HEADER_ENCODING))

        w('Status', status)
        for k, v in headers:
            w(k, v)
        output.write(b'\r\n')

    def produce(self, env, bodysize, input, output):
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
            raw_path = path.encode(HEADER_ENCODING)
            path = urllib.parse.unquote(path)
        else:
            path = ''
            raw_path = None
        if 'QUERY_STRING' in env:
            query_string = env['QUERY_STRING'].encode(HEADER_ENCODING)
        else:
            query_string = b''
        content_length = env.get('CONTENT_LENGTH')
        if content_length:
            headers.append(
                (b'content-length', content_length.encode(HEADER_ENCODING))
            )
        if bodysize:
            request_body = input.read(bodysize)
        else:
            request_body = b''
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

        message_event = asyncio.Event()

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
                self._write_response_header(
                    output, event['status'], event.get('headers') or []
                )
            elif event['type'] == 'http.response.body':
                output.write(event['body'])
                if not event.get('more_body'):
                    self._response_complete = True
                    message_event.set()
            else:
                debug('ignore unknown event')

        async def main():
            await self.app(scope, receive, send)

        asyncio.run(main())


class Handler(session_server.SCGIHandler):
    """Handler for processing incoming HTTP requests.   This gets created
    once per each worker (child) process.  The produce() method gets called
    each time there is a request to handle.
    """

    def __init__(self, parent_fd, app):
        session_server.SCGIHandler.__init__(self, parent_fd)
        self.app = app

    def produce(self, env, bodysize, input, output):
        req = RequestHandler(self.app)
        req.produce(env, bodysize, input, output)


def handler_factory(app, init=None):
    def make_handler(parent_fd):
        if init is not None:
            debug(f'running init in pid {os.getpid()}')
            init()
        return Handler(parent_fd, app)

    return make_handler


DEFAULT_HOST = 'localhost'
DEFAULT_PORT = session_server.SCGIServer.DEFAULT_PORT


def run(app, host=DEFAULT_HOST, port=None, init=None):
    if port is None:
        if len(sys.argv) == 2:
            port = int(sys.argv[1])
        else:
            port = DEFAULT_PORT
    print('scgi server running on %s:%s' % (host, port))
    session_server.SCGIServer(
        handler_class=handler_factory(app, init=init), host=host, port=port
    ).serve()


def main():
    global DEBUG
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--debug',
        default=False,
        action='store_true',
        help='Enable debugging output.',
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
    # FIXME: this should probably use a "lifespan.startup" event rather
    # this this function call.  This was simpler to implement though.
    parser.add_argument(
        '--init',
        default='',
        help='Initialize function to call for appliction post-fork.',
    )

    parser.add_argument(
        'app', help='Name of module and function to call, e.g. "myapp:app"'
    )
    args = parser.parse_args()
    DEBUG = args.debug

    # Lookup application class
    mod_name, sep, app_name = args.app.partition(':')
    if not sep:
        parser.print_usage()
        parser.exit(1, 'Invalid "app" argument, missing colon.\n')
    module = __import__(mod_name)
    app = getattr(module, app_name)

    # Lookup optional init() function for application
    if args.init:
        init_mod_name, sep, init_name = args.init.partition(':')
        init_mod = __import__(init_mod_name)
        init_func = getattr(init_mod, init_name)
    else:
        init_func = None

    run(app, host=args.host, port=args.port, init=init_func)


if __name__ == '__main__':
    main()
