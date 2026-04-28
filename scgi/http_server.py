"""HTTP server that speaks HTTP externally and SCGI internally.

The master process accepts HTTP connections (suitable for running behind
HAProxy) and distributes work to pre-forked child workers using Unix
fd-passing.  No external SCGI front-end is required.

Architecture:
    [HAProxy / browser]
        | HTTP (TCP)
        v
    Master process  (trio async)
        |- accepts HTTP, parses to SCGI env
        |- manages pool of pre-forked child workers
        v  fd-passing (socketpair + passfd)
    Child processes  (app server)
        |- receives fd via passfd.recvfd()
        |- processes SCGI request, writes SCGI response
        |- master reads response, converts to HTTP, sends to client

Per-request flow in the master:
    1. parse HTTP headers -> SCGI env dict
    2. buffer request body
    3. pick session_id (cookie or REMOTE_ADDR)
    4. get or spawn child for session_id
    5. master_sock, child_sock = socket.socketpair(AF_UNIX)
    6. pass child_sock fd to child via passfd.sendfd()
    7. write ns_pack(scgi_pack(env)) + body -> master_sock
    8. read SCGI response <- master_sock
    9. write HTTP response -> client
"""

from __future__ import annotations

import errno
import fcntl
import http.client
import io
import os
import re
import secrets
import select
import signal
import socket
import sys
import tempfile
import time
import traceback
import urllib.parse

import trio
import trio.lowlevel

from scgi import passfd
from scgi.systemd_socket import get_systemd_socket

# buffer sizes for socket reads/writes
BUF_SMALL = 1 << 12  # 4 KiB
BUF_LARGE = 1 << 23  # 8 MiB

# maximum size for HTTP request headers (DoS protection)
HEADER_MAX_SIZE = 8000

# Allow connections without PROXY protocol or X-Real-IP.
# Only enable for dev/testing; leave False in production.
ALLOW_DIRECT = False

# Pattern matching the app session cookie
SESSION_ID_PATTERN = re.compile(r'session="(?P<id>[A-Za-z0-9\\/_=+-]+)"')

DEFAULT_SESSION_ID = "*unknown*"

# Maximum number of queued connection deliveries per child before 503
MAX_QUEUE = 15

# Child is considered old and eligible for pruning after this many idle seconds
MAX_AGE = 7200

# Hard timeout: kill child unconditionally after this many idle seconds
CHILD_TIMEOUT = 600


class ProtocolError(Exception):
    pass


def log(*args) -> None:
    print(*args, flush=True)


def log_traceback() -> None:
    log(traceback.format_exc())


split_newlines = re.compile(r"\r?\n").split


# See RFC 2109 for details.  Note that this parser is more liberal.
_COOKIE_RE = re.compile(
    r"""
                \s*
                (?P<name>[^=;,\s]+)
                \s*
                (
                    =
                    \s*
                    (
                        (?P<qvalue> "(\\[\x00-\x7f] | [^"])*")
                        |
                        (?P<value> [^";,\s]*)
                    )
                )?
                \s*
                [;,]?
                """,
    re.VERBOSE,
)


def _parse_cookies(text):
    result = {}
    for m in _COOKIE_RE.finditer(text):
        name = m.group("name")
        if name[0] == "$":
            # discard, we don't handle per cookie attributes (e.g. $Path)
            continue
        qvalue = m.group("qvalue")
        if qvalue:
            value = re.sub(r"\\(.)", r"\1", qvalue)[1:-1]
        else:
            value = m.group("value") or ""
        result[name] = value
    return result


class Request:
    def __init__(self, env: dict, headers: bytes) -> None:
        self.request_id = secrets.token_hex(4)
        self.env = env
        self.headers = headers
        self.cookies = _parse_cookies(env.get("HTTP_COOKIE") or "")
        self.response_status = None

    def set_status(self, line: bytes) -> None:
        m = re.match(r"Status:\s*(\d+)", line.decode("latin1"))
        if m:
            self.response_status = m.group(1)

    def log(self, *args) -> None:
        log(self.request_id, *args)


def parse_env(
    conn, host_name: str, host_port: int | str, headers: bytes
) -> dict:
    """Parse HTTP request headers into an SCGI environment dict.

    Supports HAProxy PROXY protocol (line 1 starts with 'PROXY ').
    Falls back to X-Real-IP header if ALLOW_DIRECT is False.
    """
    lines = split_newlines(headers.decode("latin1"))
    first_line = lines[0] if lines else ""
    remote_host: str = "unknown"
    remote_port: int | str = 0
    need_real_ip = False
    if not ALLOW_DIRECT:
        if first_line.startswith("PROXY "):
            # HAProxy PROXY protocol v1, e.g.:
            # PROXY TCP4 192.168.0.1 192.168.0.11 56324 443\r\n
            parts = first_line.split()
            del lines[0]
            remote_host = parts[2]
            remote_port = parts[4]
            host_name = parts[3]
            host_port = parts[5]
        else:
            need_real_ip = True
    else:
        # ALLOW_DIRECT: clients connect directly (dev/test only)
        peer = conn.socket.getpeername()
        if isinstance(peer, tuple) and len(peer) == 2:
            remote_host, remote_port = peer
        else:
            remote_host = "unknown"
            remote_port = 0
    fp = io.BytesIO("\r\n".join(lines[1:]).encode("latin1"))
    parsed_headers = http.client.parse_headers(fp)
    if need_real_ip:
        remote_host = parsed_headers.get("x-real-ip") or ""
        remote_port = parsed_headers.get("x-real-port") or 0
        if not remote_host:
            raise ProtocolError("missing X-Real-IP header")
    parts_req = lines[0].strip().split()
    if len(parts_req) != 3:
        raise ProtocolError("invalid request line")
    method, uri, version = parts_req
    if version not in ("HTTP/1.0", "HTTP/1.1"):
        raise ProtocolError("unsupported HTTP version: %s" % version)
    path, _, qs = uri.partition("?")
    env: dict = {
        "CONTENT_LENGTH": "0",
        "SCGI": "1",
        "REQUEST_METHOD": method,
        "SCRIPT_NAME": "",
        "PATH_INFO": urllib.parse.unquote(path),
        "QUERY_STRING": qs,
        "REQUEST_URI": uri,
        "SERVER_PROTOCOL": version,
        "SERVER_SOFTWARE": "dxweb_http/1.0",
        "SERVER_NAME": host_name,
        "SERVER_PORT": str(host_port),
        "REMOTE_PORT": str(remote_port),
        "REMOTE_ADDR": remote_host,
        "HTTPS": parsed_headers.get("x-https") or "off",
    }
    if parsed_headers.get("content-type") is None:
        env["CONTENT_TYPE"] = parsed_headers.get_content_type()
    else:
        env["CONTENT_TYPE"] = parsed_headers["content-type"]
    if parsed_headers.get("transfer-encoding"):
        raise ProtocolError("Transfer-Encoding not supported")
    cl_values = parsed_headers.get_all("content-length") or []
    if len(cl_values) > 1:
        raise ProtocolError("duplicate Content-Length headers")
    length = cl_values[0] if cl_values else None
    if length:
        env["CONTENT_LENGTH"] = length
    for name in parsed_headers.keys():
        if "_" in name:
            continue  # prevent header smuggling
        values = parsed_headers.get_all(name) or []
        value = ",".join(values)
        normalized = name.replace("-", "_").upper()
        if normalized not in env:
            env["HTTP_" + normalized] = value.strip()
    return env


def scgi_pack(env: dict) -> bytes:
    """Pack env dict into SCGI header bytes (null-separated key\\0value\\0...)."""
    parts = []
    for k, v in env.items():
        parts.append("%s\0%s\0" % (k, v))
    return "".join(parts).encode("latin1")


def ns_pack(data: bytes) -> bytes:
    """Wrap bytes in a netstring: '<len>:<data>,'."""
    return b"%d:%s," % (len(data), data)


def _extract_session_id(env: dict) -> str:
    """Return a session identifier for routing to a child worker."""
    cookies = env.get("HTTP_COOKIE")
    if cookies:
        m = SESSION_ID_PATTERN.search(cookies)
        if m:
            return m.group("id")
    ip = env.get("HTTP_X_FORWARDED_FOR") or env.get("REMOTE_ADDR")
    if ip:
        return ip
    return DEFAULT_SESSION_ID


# A pending request item queued to a child worker.
# child_sock: the child's end of the per-request socketpair (to be passed via fd)
# ready_event: signaled after passfd.sendfd() succeeds (or fails)
# failed: set to True if the fd-pass failed
class _PendingRequest:
    __slots__ = ("child_sock", "ready_event", "failed")

    def __init__(self, child_sock: socket.socket) -> None:
        self.child_sock = child_sock
        self.ready_event = trio.Event()
        self.failed = False


class Child:
    """Represents a pre-forked worker process.

    The master communicates with each child via a Unix socketpair (child_fd).
    The child signals readiness by writing b'1' to its end; the master reads
    that byte and then passes the next connection fd via passfd.sendfd().
    """

    def __init__(self, session_id: str, pid: int, child_fd: int) -> None:
        self.session_id = session_id
        self.pid = pid
        self.child_fd = child_fd  # master's end of the control socketpair
        self.closed = False
        self.last_used = time.time()
        # channel of _PendingRequest items
        self._send_chan: trio.MemorySendChannel[_PendingRequest]
        self._recv_chan: trio.MemoryReceiveChannel[_PendingRequest]
        self._send_chan, self._recv_chan = trio.open_memory_channel(MAX_QUEUE)

    def log(self, msg: str) -> None:
        log("%s (pid=%s)" % (msg, self.pid))

    def get_age(self) -> float:
        return time.time() - self.last_used

    def close(self) -> None:
        if not self.closed:
            os.close(self.child_fd)
            # Close only the send side.  Closing the receive side would
            # discard already-queued pending items (so their waiters in
            # process_request would hang) and make the watcher's drain
            # loop raise ClosedResourceError — which previously crashed
            # the master.  Closing the send side signals EndOfChannel to
            # the watcher cleanly.
            self._send_chan.close()
            self.closed = True

    def enqueue(self, pending: _PendingRequest) -> bool:
        """Queue a pending request.  Returns False if the queue is full."""
        try:
            self._send_chan.send_nowait(pending)
            return True
        except trio.WouldBlock:
            self.log("server busy")
            return False

    async def watcher(self) -> None:
        """Per-child trio task: pair queued requests with child readiness bytes.

        The child protocol (from scgi.util.SCGIHandler.serve):
            loop: write b'1' (ready) → recvfd → handle request → repeat

        So we must:
            1. Dequeue the next pending request (wait if none yet).
            2. Wait for the child's readiness byte.
            3. Pass the fd via passfd.sendfd().

        Steps 1 and 2 can be done in either order since both are independent,
        but consuming the readiness byte before we have a request to send would
        lose it.  Waiting for the request first is safe because the child always
        writes its byte independently of us.
        """
        while not self.closed:
            # get the next request to deliver.
            try:
                pending = await self._recv_chan.receive()
            except trio.EndOfChannel:
                break

            # wait for the child's readiness byte.
            failed = False
            while True:
                try:
                    await trio.lowlevel.wait_readable(self.child_fd)
                except Exception:
                    failed = True
                    break
                try:
                    ready_byte = os.read(self.child_fd, 1)
                    if not ready_byte:
                        failed = True
                    break
                except OSError as exc:
                    if exc.errno == errno.EWOULDBLOCK:
                        continue  # spurious wakeup, try again
                    failed = True
                    break

            if failed:
                pending.child_sock.close()
                pending.failed = True
                pending.ready_event.set()
                self.close()
                break

            # pass the fd to the child.
            self.last_used = time.time()
            try:
                passfd.sendfd(self.child_fd, pending.child_sock.fileno())
            except OSError as exc:
                if exc.errno == errno.EPIPE:
                    self.log("EPIPE passing fd to child")
                else:
                    self.log("OSError passing fd: %s" % exc.errno)
                pending.child_sock.close()
                pending.failed = True
                pending.ready_event.set()
                self.close()
                break
            pending.child_sock.close()
            pending.ready_event.set()

        # drain remaining queued requests with failure
        try:
            while True:
                pending = self._recv_chan.receive_nowait()
                pending.child_sock.close()
                pending.failed = True
                pending.ready_event.set()
        except (trio.WouldBlock, trio.EndOfChannel, trio.ClosedResourceError):
            pass


class HTTPServer:
    """HTTP front-end server that dispatches to pre-forked application workers.

    The master process speaks HTTP externally (supports HAProxy PROXY protocol)
    and communicates with pre-forked child workers via Unix fd-passing.
    Child management (session affinity, pruning, reaping) mirrors
    scgi.session_server.SCGIServer.
    """

    def __init__(
        self,
        host: str,
        port: int,
        create_handler,
        max_children: int = 5,
    ) -> None:
        self.host = host
        self.port = port
        self.create_handler = create_handler
        self.max_children = max_children
        self.host_name = socket.getfqdn(host)
        self.children: dict[str, Child] = {}
        self.last_prune = 0.0
        self._nursery = None

    def _spawn_child(self, session_id: str) -> Child:
        """Fork a new worker process and register it."""
        # control socketpair: parent_fd stays in master, child_fd goes to child
        parent_fd, child_fd = passfd.socketpair(
            socket.AF_UNIX, socket.SOCK_STREAM
        )
        # make parent_fd non-blocking so wait_readable works correctly
        flags = fcntl.fcntl(parent_fd, fcntl.F_GETFL, 0)
        fcntl.fcntl(parent_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        pid = os.fork()
        if pid == 0:
            # child process: close parent_fd and all other children's fds
            os.close(parent_fd)
            for ch in self.children.values():
                if not ch.closed:
                    os.close(ch.child_fd)
            # Ignore SIGINT in children — the master handles Ctrl-C and
            # shuts children down by closing their socketpairs.
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            # The child must stay in pure sync code after fork: trio's epoll
            # fd is duplicated by fork(), so any trio activity here would
            # share epoll state with the parent and corrupt its I/O.  Run
            # the SCGI loop synchronously and bypass trio entirely on exit
            # via os._exit, so SystemExit raised by SCGIHandler.serve on
            # parent disconnect doesn't propagate into the parent nursery
            # as a noisy ExceptionGroup.
            try:
                self.create_handler(child_fd).serve()
            except SystemExit:
                pass
            except BaseException:
                traceback.print_exc()
                sys.stdout.flush()
                sys.stderr.flush()
                os._exit(1)
            os._exit(0)
        else:
            os.close(child_fd)
            child = Child(session_id, pid, parent_fd)
            self.children[session_id] = child
            log(
                "started child (session=%s pid=%s nchild=%s)"
                % (session_id, pid, len(self.children))
            )
            if self._nursery is not None:
                self._nursery.start_soon(child.watcher)
            return child

    def _reap_children(self) -> None:
        while self.children:
            try:
                pid, _status = os.waitpid(-1, os.WNOHANG)
            except OSError:
                break
            if pid <= 0:
                break
            for sid, child in list(self.children.items()):
                if child.pid == pid:
                    child.close()
                    del self.children[sid]
                    log("reaped child pid=%s" % pid)
                    break

    def _is_old(self, child: Child) -> bool:
        n = len(self.children)
        max_age = max(10.0, MAX_AGE / n) if n else float(MAX_AGE)
        age = child.get_age()
        if age < max_age:
            return False
        if age > CHILD_TIMEOUT:
            return True
        try:
            r, _w, _e = select.select([child.child_fd], [], [], 0)
            return bool(r)
        except Exception:
            return False

    def _prune_children(self) -> None:
        now = time.time()
        if now - self.last_prune < 20:
            return
        self.last_prune = now
        for child in list(self.children.values()):
            if child.closed or self._is_old(child):
                log(
                    "closing old child (pid=%s nchild=%s)"
                    % (child.pid, len(self.children) - 1)
                )
                child.close()
                sid = child.session_id
                if sid in self.children:
                    del self.children[sid]
        self._reap_children()

    def _get_or_spawn_child(self, session_id: str) -> Child:
        child = self.children.get(session_id)
        if child is None or child.closed:
            child = self._spawn_child(session_id)
        return child

    def get_listening_socket(self) -> socket.socket:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host, self.port))
        return s

    async def read_env(self, conn) -> tuple[Request, bytes]:
        """Read HTTP request headers from client; return (Request, leftover)."""
        buf = b""
        sep = re.compile(b"\r?\n\r?\n")
        while True:
            chunk = await conn.receive_some(BUF_SMALL)
            if not chunk:
                raise ProtocolError("end of stream reading headers")
            buf += chunk
            if sep.search(buf):
                break
            if len(buf) >= HEADER_MAX_SIZE:
                raise ProtocolError("HTTP headers too large")
        headers, leftover = sep.split(buf, 1)
        env = parse_env(conn, self.host_name, self.port, headers)
        req = Request(env, headers)
        return req, leftover

    async def read_status(self, req: Request, conn) -> bytes:
        """Read SCGI response until first newline; return rewritten prefix."""
        buf = b""
        while True:
            chunk = await conn.receive_some(BUF_SMALL)
            if not chunk:
                raise ProtocolError("end of stream reading SCGI response")
            buf += chunk
            if b"\n" in buf:
                break
            if len(buf) >= HEADER_MAX_SIZE:
                raise ProtocolError("Did not find Status header")
        lines = buf.split(b"\n")
        status = lines[0]
        req.set_status(status)
        if not req.response_status:
            raise ProtocolError("Response does not have valid Status header")
        lines[0] = status.replace(b"Status:", b"HTTP/1.1")
        # Insert Connection: close so the browser doesn't try to reuse the
        # connection.  Our server has no keep-alive support.
        lines.insert(1, b"Connection: close\r")
        return b"\n".join(lines)

    async def process_request(self, client_conn) -> None:
        req, leftover = await self.read_env(client_conn)
        content_length = int(req.env.get("CONTENT_LENGTH") or 0)

        # buffer request body
        req_file = tempfile.SpooledTemporaryFile(max_size=500_000)
        n = len(leftover)
        req_file.write(leftover)
        while n < content_length:
            buf = await client_conn.receive_some(BUF_LARGE)
            if not buf:
                raise ProtocolError("end of stream reading request body")
            n += len(buf)
            req_file.write(buf)
        req_file.seek(0)

        session_id = _extract_session_id(req.env)
        child = self._get_or_spawn_child(session_id)

        # create a socketpair for this request's SCGI data:
        #   master_sock  — stays in master, used for async I/O via trio
        #   child_raw    — passed to the child worker via fd-passing
        master_raw, child_raw = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_STREAM
        )
        master_sock = trio.socket.from_stdlib_socket(master_raw)

        pending = _PendingRequest(child_raw)
        if not child.enqueue(pending):
            master_sock.close()
            child_raw.close()
            req_file.close()
            body = (
                b"<html><body><h1>Service Temporarily Unavailable</h1>"
                b"Please try again later.</body></html>"
            )
            await client_conn.send_all(
                b"HTTP/1.1 503 Service Temporarily Unavailable\r\n"
                b"Content-Type: text/html\r\nConnection: close\r\n"
                b"Content-Length: "
                + str(len(body)).encode()
                + b"\r\n\r\n"
                + body
            )
            return

        # wait for the watcher task to deliver child_raw to the child
        await pending.ready_event.wait()
        if pending.failed:
            master_sock.close()
            req_file.close()
            raise ProtocolError("failed to pass fd to child worker")

        # wrap as a trio stream for consistent async I/O
        master_stream = trio.SocketStream(master_sock)

        # write SCGI request: netstring-wrapped env headers + body
        await master_stream.send_all(ns_pack(scgi_pack(req.env)))
        while True:
            buf = req_file.read(BUF_LARGE)
            if not buf:
                break
            await master_stream.send_all(buf)
        req_file.close()
        # signal EOF on the write side so child sees end-of-request body
        master_sock.shutdown(socket.SHUT_WR)

        # read and spool the full SCGI response before touching the client.
        # This frees the child worker as soon as it finishes writing, rather
        # than tying it up while a slow client drains the response.
        buf = await self.read_status(req, master_stream)
        res_file = tempfile.SpooledTemporaryFile(max_size=500_000)
        while True:
            res_file.write(buf)
            buf = await master_stream.receive_some(BUF_LARGE)
            if not buf:
                break
        await master_stream.aclose()
        res_file.seek(0)

        # stream HTTP response back to client
        while True:
            buf = res_file.read(BUF_LARGE)
            if not buf:
                break
            try:
                await client_conn.send_all(buf)
            except trio.BrokenResourceError:
                req.log("broken pipe sending response to client")
                break
        res_file.close()
        self._prune_children()

    async def serve_one_connection(self, stream) -> None:
        try:
            await self.process_request(stream)
            await stream.aclose()
        except Exception:
            log("error while processing request")
            log_traceback()

    async def serve_on_socket(self, sock) -> None:
        sock.listen(40)
        listener = trio.SocketListener(sock)
        async with trio.open_nursery() as nursery:
            self._nursery = nursery
            await trio.serve_listeners(self.serve_one_connection, [listener])

    async def serve(self) -> None:
        sock = get_systemd_socket()
        if sock is not None:
            log("Using inherited socket %r" % (sock.getsockname(),))
        else:
            sock = self.get_listening_socket()
        sock = trio.socket.from_stdlib_socket(sock)
        await self.serve_on_socket(sock)
