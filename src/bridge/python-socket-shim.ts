/**
 * Python Virtual Socket Shim Bootstrap Code.
 * Injected into Pyodide runtime upon worker initialization.
 * Intercepts `import socket` and routes all calls synchronously
 * to the co-located `js_sim_core` JavaScript bridge.
 */
export const PYTHON_SOCKET_SHIM_CODE = `
import sys
import types
import io

def _bootstrap_socket_shim(_sim_core_bridge):
    def _to_bytes(data):
        if isinstance(data, memoryview):
            return data.tobytes()
        if isinstance(data, bytearray):
            return bytes(data)
        if isinstance(data, bytes):
            return data
        if isinstance(data, str):
            return data.encode('utf-8')
        if hasattr(data, '__bytes__'):
            return bytes(data)
        return bytes(data)

    _SERVICE_PORTS = {
        'http': 80,
        'https': 443,
        'ssh': 22,
        'ftp': 21,
        'telnet': 23,
        'smtp': 25,
        'dns': 53,
        'domain': 53,
        'pop3': 110,
        'imap': 143,
    }

    def _parse_port(port):
        if port is None or port == '':
            return 0
        if isinstance(port, int):
            return port
        if isinstance(port, str):
            if port.isdigit():
                return int(port)
            lower = port.lower()
            if lower in _SERVICE_PORTS:
                return _SERVICE_PORTS[lower]
        try:
            return int(port)
        except Exception:
            raise OSError(f"getaddrinfo: servname not known for port {port}")

    class _SocketIO(io.RawIOBase):
        def __init__(self, sock, mode='r', encoding=None, errors=None, newline=None):
            super().__init__()
            self._sock = sock
            self._mode = mode
            self._encoding = encoding or 'utf-8'
            self._errors = errors or 'strict'

        def readinto(self, b):
            data = self._sock.recv(len(b))
            if not data:
                return 0
            n = len(data)
            b[:n] = data
            return n

        def read(self, size=-1):
            if size < 0:
                size = 4096
            data = self._sock.recv(size)
            if 'b' not in self._mode:
                return data.decode(self._encoding, self._errors)
            return data

        def readline(self, size=-1):
            res = bytearray()
            while size < 0 or len(res) < size:
                ch = self._sock.recv(1)
                if not ch:
                    break
                res.extend(ch)
                if ch == b'\\n':
                    break
            if 'b' not in self._mode:
                return res.decode(self._encoding, self._errors)
            return bytes(res)

        def write(self, b):
            if isinstance(b, str):
                b = b.encode(self._encoding, self._errors)
            return self._sock.send(b)

        def flush(self):
            pass

        def readable(self):
            return True

        def writable(self):
            return True

        def seekable(self):
            return False

        def close(self):
            super().close()

    class VirtualSocket:
        AF_INET = 2
        SOCK_STREAM = 1
        SOCK_DGRAM = 2
        SOL_SOCKET = 1
        SO_REUSEADDR = 2

        def __init__(self, family=AF_INET, type=SOCK_STREAM, proto=0, _fd=None):
            self.family = family
            self.type = type
            self.proto = proto
            self.timeout = None
            self.closed = False
            self._bound_addr = None
            self._peer_addr = None
            self._blocking = True

            if _fd is not None:
                self.fd = int(_fd)
            else:
                self.fd = int(_sim_core_bridge.createSocket(int(family), int(type)))

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            self.close()

        def setblocking(self, flag):
            self._blocking = bool(flag)
            if not self._blocking:
                self.settimeout(0.0)
            else:
                self.settimeout(None)

        def getblocking(self):
            return self._blocking

        def makefile(self, mode='r', buffering=-1, encoding=None, errors=None, newline=None):
            return _SocketIO(self, mode, encoding=encoding, errors=errors, newline=newline)

        def settimeout(self, timeout):
            self.timeout = float(timeout) if timeout is not None else None
            _sim_core_bridge.setSocketTimeout(self.fd, self.timeout)

        def gettimeout(self):
            return self.timeout

        def connect(self, address):
            res = self.connect_ex(address)
            if res == 0:
                return None
            elif res == 110:
                raise TimeoutError("Connection timed out")
            elif res == 111:
                raise ConnectionRefusedError("Connection refused")
            elif res == 113:
                raise OSError(113, "No route to host")
            else:
                raise OSError(res, f"Socket error: {res}")

        def connect_ex(self, address):
            if self.closed:
                raise OSError(9, "Bad file descriptor")
            if not isinstance(address, (tuple, list)) or len(address) < 2:
                raise TypeError("AF_INET address must be a tuple (host, port)")
            ip = str(address[0])
            port = int(address[1])
            res = _sim_core_bridge.connectSocket(self.fd, ip, port, self.timeout)
            errno_val = int(getattr(res, 'errno', res.get('errno') if isinstance(res, dict) else 111))
            if errno_val == 0:
                conn_ip = getattr(res, 'connectedIp', res.get('connectedIp') if isinstance(res, dict) else None)
                conn_port = getattr(res, 'connectedPort', res.get('connectedPort') if isinstance(res, dict) else None)
                if conn_ip:
                    self._peer_addr = (str(conn_ip), int(conn_port))
                else:
                    self._peer_addr = (str(_sim_core_bridge.resolveDns(ip)), port)
                bound_ip = getattr(res, 'boundIp', res.get('boundIp') if isinstance(res, dict) else None)
                bound_port = getattr(res, 'boundPort', res.get('boundPort') if isinstance(res, dict) else None)
                if bound_port:
                    self._bound_addr = (str(bound_ip), int(bound_port))
            return errno_val

        def send(self, data):
            if self.closed:
                raise OSError(9, "Bad file descriptor")
            if not self._peer_addr:
                raise OSError(107, "Transport endpoint is not connected")
            b = _to_bytes(data)
            sent = _sim_core_bridge.sendSocket(self.fd, b)
            return int(sent)

        def sendall(self, data):
            return self.send(data)

        def sendto(self, data, address):
            if self.closed:
                raise OSError(9, "Bad file descriptor")
            if not isinstance(address, (tuple, list)) or len(address) < 2:
                raise TypeError("AF_INET address must be a tuple (host, port)")
            ip = str(address[0])
            port = int(address[1])
            b = _to_bytes(data)
            if hasattr(_sim_core_bridge, 'sendToSocket'):
                sent = _sim_core_bridge.sendToSocket(self.fd, ip, port, b)
            else:
                sent = _sim_core_bridge.sendSocket(self.fd, b)
            if not self._bound_addr and hasattr(_sim_core_bridge, 'getSockName'):
                name_info = _sim_core_bridge.getSockName(self.fd)
                if name_info:
                    act_ip = getattr(name_info, 'ip', None) if not isinstance(name_info, dict) else name_info.get('ip')
                    act_port = getattr(name_info, 'port', None) if not isinstance(name_info, dict) else name_info.get('port')
                    if act_port:
                        self._bound_addr = (str(act_ip) if act_ip else '0.0.0.0', int(act_port))
            return int(sent)

        def recv(self, bufsize):
            if not self._peer_addr:
                raise OSError(107, "Transport endpoint is not connected")
            if int(bufsize) <= 0 or self.closed:
                return b""
            try:
                raw_bytes = _sim_core_bridge.recvSocket(self.fd, int(bufsize))
                if raw_bytes is None:
                    return b""
                if hasattr(raw_bytes, 'to_py'):
                    return bytes(raw_bytes.to_py())
                return bytes(raw_bytes)
            except Exception:
                return b""

        def recvfrom(self, bufsize):
            if self.closed:
                raise OSError(9, "Bad file descriptor")
            if int(bufsize) <= 0:
                return (b"", ('0.0.0.0', 0))
            if hasattr(_sim_core_bridge, 'recvFromSocket'):
                res = _sim_core_bridge.recvFromSocket(self.fd, int(bufsize))
                if res is not None:
                    raw = getattr(res, 'data', res.get('data') if isinstance(res, dict) else b"")
                    ip = getattr(res, 'ip', res.get('ip') if isinstance(res, dict) else '0.0.0.0')
                    port = getattr(res, 'port', res.get('port') if isinstance(res, dict) else 0)
                    try:
                        data_bytes = bytes(raw.to_py()) if hasattr(raw, 'to_py') else bytes(raw)
                    except Exception:
                        try:
                            data_bytes = bytes(raw)
                        except Exception:
                            data_bytes = memoryview(raw).tobytes() if isinstance(raw, memoryview) else bytes(raw)
                    return (data_bytes, (str(ip), int(port)))
            if self.type == self.SOCK_DGRAM:
                return (b"", ('0.0.0.0', 0))
            data_bytes = self.recv(bufsize)
            addr = self._peer_addr or ('0.0.0.0', 0)
            return (data_bytes, addr)

        def bind(self, address):
            if self.closed:
                raise OSError(9, "Bad file descriptor")
            if not isinstance(address, (tuple, list)) or len(address) < 2:
                raise TypeError("AF_INET address must be a tuple (host, port)")
            raw_ip = str(address[0]) if address[0] is not None else ''
            port = int(address[1])
            res = _sim_core_bridge.bindSocket(self.fd, raw_ip, port)
            errno_val = int(getattr(res, 'errno', res.get('errno') if isinstance(res, dict) else 22))
            if errno_val != 0:
                raise OSError(errno_val, "Bind failed")
            act_port = port
            act_ip = raw_ip if raw_ip else '0.0.0.0'
            if hasattr(_sim_core_bridge, 'getSockName'):
                name_info = _sim_core_bridge.getSockName(self.fd)
                if name_info:
                    b_ip = getattr(name_info, 'ip', None) if not isinstance(name_info, dict) else name_info.get('ip')
                    b_port = getattr(name_info, 'port', None) if not isinstance(name_info, dict) else name_info.get('port')
                    if b_port is not None and int(b_port) > 0:
                        act_port = int(b_port)
                    if b_ip is not None and str(b_ip):
                        if raw_ip and raw_ip != '0.0.0.0':
                            act_ip = str(b_ip)
                        else:
                            act_ip = '0.0.0.0'
            self._bound_addr = (act_ip, act_port)

        def listen(self, backlog=5):
            if self.closed:
                raise OSError(9, "Bad file descriptor")
            _sim_core_bridge.listenSocket(self.fd, int(backlog))
            if hasattr(_sim_core_bridge, 'getSockName'):
                name_info = _sim_core_bridge.getSockName(self.fd)
                if name_info:
                    l_ip = getattr(name_info, 'ip', None) if not isinstance(name_info, dict) else name_info.get('ip')
                    l_port = getattr(name_info, 'port', None) if not isinstance(name_info, dict) else name_info.get('port')
                    if l_ip is not None and l_port is not None:
                        cur_ip = self._bound_addr[0] if self._bound_addr else str(l_ip)
                        self._bound_addr = (cur_ip, int(l_port))

        def accept(self):
            if self.closed:
                raise OSError(9, "Bad file descriptor")
            client_res = _sim_core_bridge.acceptSocket(self.fd)
            errno_val = int(getattr(client_res, 'errno', client_res.get('errno') if isinstance(client_res, dict) else 111))
            if errno_val != 0:
                raise OSError(errno_val, "Accept failed")
            cfd = int(getattr(client_res, 'clientFd', client_res.get('clientFd') if isinstance(client_res, dict) else 0))
            cip = str(getattr(client_res, 'clientIp', client_res.get('clientIp') if isinstance(client_res, dict) else '0.0.0.0'))
            cport = int(getattr(client_res, 'clientPort', client_res.get('clientPort') if isinstance(client_res, dict) else 0))
            client_sock = VirtualSocket(family=self.family, type=self.type, proto=self.proto, _fd=cfd)
            if hasattr(_sim_core_bridge, 'getSockName'):
                name_info = _sim_core_bridge.getSockName(cfd)
                if name_info:
                    srv_ip = getattr(name_info, 'ip', None) if not isinstance(name_info, dict) else name_info.get('ip')
                    srv_port = getattr(name_info, 'port', None) if not isinstance(name_info, dict) else name_info.get('port')
                    if srv_ip is not None and srv_port is not None:
                        client_sock._bound_addr = (str(srv_ip), int(srv_port))
            if not client_sock._bound_addr:
                client_sock._bound_addr = self._bound_addr
            client_sock._peer_addr = (cip, cport)
            return client_sock, (cip, cport)

        def getsockname(self):
            if self.closed:
                raise OSError(9, "Bad file descriptor")
            if self._bound_addr and self._bound_addr[1] != 0:
                return self._bound_addr
            if hasattr(_sim_core_bridge, 'getSockName'):
                name_info = _sim_core_bridge.getSockName(self.fd)
                if name_info:
                    ip = getattr(name_info, 'ip', None) if not isinstance(name_info, dict) else name_info.get('ip')
                    port = getattr(name_info, 'port', None) if not isinstance(name_info, dict) else name_info.get('port')
                    if ip is not None:
                        res_port = int(port or 0)
                        res_ip = str(ip)
                        if self._bound_addr and self._bound_addr[0] == '0.0.0.0' and not self._peer_addr:
                            res_ip = '0.0.0.0'
                        res = (res_ip, res_port)
                        if res[1] != 0:
                            self._bound_addr = res
                        return res
            return self._bound_addr or ('0.0.0.0', 0)

        def getpeername(self):
            if self.closed:
                raise OSError(9, "Bad file descriptor")
            if self._peer_addr:
                return self._peer_addr
            peer_info = _sim_core_bridge.getPeerName(self.fd)
            if peer_info:
                ip = getattr(peer_info, 'ip', None) if not isinstance(peer_info, dict) else peer_info.get('ip')
                port = getattr(peer_info, 'port', None) if not isinstance(peer_info, dict) else peer_info.get('port')
                if ip is not None and port is not None:
                    self._peer_addr = (str(ip), int(port))
                    return self._peer_addr
            raise OSError(107, "Transport endpoint is not connected")

        def setsockopt(self, level, optname, value):
            pass

        def getsockopt(self, level, optname, buflen=0):
            return 0

        def fileno(self):
            return self.fd

        def close(self):
            if not self.closed:
                self.closed = True
                _sim_core_bridge.closeSocket(self.fd)

    # Build replacement socket module
    sock_mod = types.ModuleType("socket")
    sock_mod.socket = VirtualSocket
    sock_mod.SocketType = VirtualSocket
    sock_mod.AF_UNSPEC = 0
    sock_mod.AF_INET = 2
    sock_mod.AF_INET6 = 10
    sock_mod.SOCK_STREAM = 1
    sock_mod.SOCK_DGRAM = 2
    sock_mod.SOCK_RAW = 3
    sock_mod.SOL_SOCKET = 1
    sock_mod.SO_REUSEADDR = 2
    sock_mod.SO_ERROR = 4
    sock_mod.SO_BROADCAST = 6
    sock_mod.SO_KEEPALIVE = 9
    sock_mod.IPPROTO_IP = 0
    sock_mod.IPPROTO_ICMP = 1
    sock_mod.IPPROTO_TCP = 6
    sock_mod.IPPROTO_UDP = 17
    sock_mod.TCP_NODELAY = 1
    sock_mod.SHUT_RD = 0
    sock_mod.SHUT_WR = 1
    sock_mod.SHUT_RDWR = 2
    sock_mod.AI_PASSIVE = 1
    sock_mod.AI_CANONNAME = 2
    sock_mod.AI_NUMERICHOST = 4
    sock_mod.AI_NUMERICSERV = 8
    sock_mod.NI_NUMERICHOST = 1
    sock_mod.NI_NUMERICSERV = 2
    sock_mod.EWOULDBLOCK = 11
    sock_mod.EAGAIN = 11
    sock_mod.EINVAL = 22
    sock_mod.ECONNREFUSED = 111
    sock_mod.ETIMEDOUT = 110
    sock_mod.EHOSTUNREACH = 113
    sock_mod.timeout = TimeoutError
    sock_mod.error = OSError
    sock_mod.herror = OSError

    class gaierror(OSError):
        pass

    sock_mod.gaierror = gaierror

    def _gethostbyname(host):
        try:
            return str(_sim_core_bridge.resolveDns(str(host)))
        except Exception:
            raise gaierror(-2, f"Name or service not known: {host}")

    def _getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
        p = _parse_port(port)
        if host is None or host == '':
            if flags & 1:  # AI_PASSIVE
                resolved = '0.0.0.0'
            else:
                resolved = '127.0.0.1'
        else:
            try:
                resolved = str(_sim_core_bridge.resolveDns(str(host)))
            except Exception:
                raise gaierror(-2, f"Name or service not known: {host}")
        fam = family if family else VirtualSocket.AF_INET
        socktype = type if type else VirtualSocket.SOCK_STREAM
        return [(fam, socktype, proto or 0, '', (resolved, p))]

    sock_mod.gethostbyname = _gethostbyname
    sock_mod.getaddrinfo = _getaddrinfo

    def inet_aton(ip_string):
        if not isinstance(ip_string, str):
            raise OSError("illegal IP address string passed to inet_aton")
        parts = ip_string.split('.')
        if len(parts) != 4:
            raise OSError("illegal IP address string passed to inet_aton")
        byte_vals = []
        for p in parts:
            if not p.isdigit():
                raise OSError("illegal IP address string passed to inet_aton")
            val = int(p)
            if val < 0 or val > 255:
                raise OSError("illegal IP address string passed to inet_aton")
            if len(p) > 1 and p.startswith('0'):
                raise OSError("illegal IP address string passed to inet_aton")
            byte_vals.append(val)
        return bytes(byte_vals)

    def inet_ntoa(packed_ip):
        b = bytes(packed_ip)
        if len(b) != 4:
            raise OSError("packed IP wrong length for inet_ntoa")
        return '.'.join(str(x) for x in b)

    sock_mod.inet_aton = inet_aton
    sock_mod.inet_ntoa = inet_ntoa

    sys.modules['socket'] = sock_mod

# Execute bootstrap with the bridge facade object
_bootstrap_socket_shim(js_sim_core)
del _bootstrap_socket_shim

# --- Adversarial Sandbox Hardening ---
_BLOCKED_MODS = {
    'js', 'pyodide_js', 'ctypes', '_posixsubprocess',
    'micropip', 'pyodide.ffi', 'pyodide.code'
}

# 1. Custom MetaPathFinder to block imports at the lowest Python module resolution level
class _SandboxFinder:
    def find_spec(self, fullname, path, target=None):
        base = fullname.split('.')[0]
        if fullname in _BLOCKED_MODS or base in {'js', 'pyodide_js', 'ctypes', '_posixsubprocess', 'micropip'}:
            raise ImportError(f"Importing '{fullname}' is restricted by sandbox security policy")
        if fullname.startswith('pyodide.ffi') or fullname.startswith('pyodide.code'):
            raise ImportError(f"Importing '{fullname}' is restricted by sandbox security policy")
        return None

sys.meta_path.insert(0, _SandboxFinder())

# 2. Hook __builtins__.__import__ and builtins.__import__
def _make_safe_import(original_import):
    def _safe_import(name, *args, **kwargs):
        base = name.split('.')[0]
        if base in {'js', 'pyodide_js', 'ctypes', '_posixsubprocess', 'micropip'} or name.startswith(('pyodide.ffi', 'pyodide.code')):
            raise ImportError(f"Importing '{name}' is restricted by sandbox security policy")
        return original_import(name, *args, **kwargs)
    return _safe_import

try:
    _real_builtin_import = __builtins__.__import__ if hasattr(__builtins__, '__import__') else __import__
    if isinstance(__builtins__, dict):
        __builtins__['__import__'] = _make_safe_import(_real_builtin_import)
    else:
        setattr(__builtins__, '__import__', _make_safe_import(_real_builtin_import))
except Exception:
    pass

try:
    import builtins
    if hasattr(builtins, '__import__'):
        builtins.__import__ = _make_safe_import(builtins.__import__)
except Exception:
    pass

# 3. Hook importlib.import_module if present
try:
    import importlib
    _real_import_mod = importlib.import_module
    def _safe_import_mod(name, package=None):
        base = name.split('.')[0]
        if base in {'js', 'pyodide_js', 'ctypes', '_posixsubprocess', 'micropip'} or name.startswith(('pyodide.ffi', 'pyodide.code')):
            raise ImportError(f"Importing '{name}' is restricted by sandbox security policy")
        return _real_import_mod(name, package)
    importlib.import_module = _safe_import_mod
except Exception:
    pass

# 4. Strip pyodide dangerous sub-APIs
try:
    import pyodide
    if hasattr(pyodide, 'code') and hasattr(pyodide.code, 'run_js'):
        delattr(pyodide.code, 'run_js')
except Exception:
    pass

# 5. Revoke blocked modules from sys.modules
for mod_name in ['pyodide_js', 'ctypes', 'js', '_posixsubprocess', 'micropip']:
    if mod_name in sys.modules:
        del sys.modules[mod_name]
    sys.modules[mod_name] = None

# 6. Cleanup global namespace: purge bridge references
for key in ['js_sim_core', '_sim_core', '_sim_core_bridge']:
    if key in globals():
        del globals()[key]
`;
