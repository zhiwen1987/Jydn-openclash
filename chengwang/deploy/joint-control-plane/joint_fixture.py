"""Linux-only private-network fixture for DoT, subscription HTTPS and read-only Mihomo."""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.server
import importlib.util
import json
import os
import pathlib
import signal
import socket
import socketserver
import ssl
import struct
import threading
import time

HERE = pathlib.Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("joint_fixture_contract", HERE / "contract.py")
C = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(C)

class Rejected(Exception): pass

def read_json(path, maximum=1 << 20):
    p = pathlib.Path(path); raw = p.read_bytes()
    if p.is_symlink() or not raw or len(raw) > maximum: raise Rejected()
    return json.loads(raw)

class State:
    def __init__(self, root, config):
        self.root, self.config = pathlib.Path(root), config
        self.lock, self.ordinal, self.connections = threading.Lock(), 0, 0
        self.event_path = self.root / "wire-events.jsonl"
        fd = os.open(self.event_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600); os.close(fd)
    def event(self, service, event, **fields):
        safe = {"schema": C.WIRE_SCHEMA, "ordinal": 0, "service": service, "event": event,
                "reference": fields.get("reference", ""), "method": fields.get("method", ""),
                "path": fields.get("path", ""), "status": fields.get("status", 0),
                "bytes": fields.get("bytes", 0), "fixturePid": os.getpid(),
                "connection": fields.get("connection", ""), "sourceHost": fields.get("sourceHost", ""),
                "tlsClass": fields.get("tlsClass", "unknown"), "authClass": fields.get("authClass", "unknown"),
                "responseClass": fields.get("responseClass", "unknown"),
                "receivedUnixNano": str(time.time_ns())}
        with self.lock:
            if self.ordinal >= C.MAX_EVENTS: raise Rejected()
            self.ordinal += 1; safe["ordinal"] = self.ordinal
            raw = C.canonical(safe)
            fd = os.open(self.event_path, os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0))
            try: os.write(fd, raw); os.fsync(fd)
            finally: os.close(fd)

def phase(state):
    value = read_json(state.root / "phase.private.json", 4096)
    if set(value) != {"successBody", "failureStatus"}: raise Rejected()
    body = base64.b64decode(value["successBody"], validate=True)
    if not body or len(body) > 1 << 20 or value["failureStatus"] not in (200, 503): raise Rejected()
    return body, value["failureStatus"]

class TLSHTTP(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = False; allow_reuse_address = False
    def __init__(self, address, handler, context, state, service):
        super().__init__(address, handler, bind_and_activate=False); self.state, self.service = state, service
        self.socket = context.wrap_socket(socket.socket(), server_side=True); self.server_bind(); self.server_activate()

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *unused): pass
    def send(self, status, body, kind="application/json"):
        self.send_response(status); self.send_header("Content-Type", kind); self.send_header("Content-Length", str(len(body))); self.send_header("Connection", "close"); self.end_headers(); self.wfile.write(body)
        source=self.server.service=="source";accepted=status in (200,503) if source else status==200
        classification="success" if status==200 else "upstream_failure" if status==503 else "denied"
        self.server.state.event(self.server.service, "response", method=self.command, path=self.path.split("?",1)[0], status=status, bytes=len(body), reference=getattr(self, "reference", ""), sourceHost=self.headers.get("Host","").split(":",1)[0], connection=self.server.service+"-"+str(self.connection.fileno())+"-"+str(time.time_ns()),tlsClass="server_tls",authClass=("source_secret_accepted" if source else "readonly_bearer_accepted") if accepted else "rejected",responseClass=classification)
    def do_GET(self):
        if self.server.service == "source": self.source_get()
        else: self.mihomo_get()
    def reject_non_get(self):
        self.reference = ""
        self.send(405, b"method not allowed\n", "text/plain")
    do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_CONNECT = do_TRACE = reject_non_get
    def source_get(self):
        host = self.headers.get("Host", "").split(":",1)[0]
        refs = {v:k for k,v in C.SOURCE_HOSTS.items()}; self.reference = refs.get(host, "")
        token = self.server.state.config.get("sourceTokens", {}).get(self.reference)
        expected = "/subscription?token=" + token if token else ""
        if not token or self.path != expected or set(self.headers) - {"Host","User-Agent","Accept-Encoding","Connection"}:
            self.send(404, b"not found\n", "text/plain"); return
        body, failure = phase(self.server.state)
        if self.reference == "success": self.send(200, body, "text/yaml")
        elif self.reference == "failure": self.send(failure, body if failure == 200 else b"upstream unavailable\n", "text/yaml")
        else: self.send(404, b"not found\n", "text/plain")
    def mihomo_get(self):
        allowed = {"/version": {"version":"joint-fixture"}, "/configs": {"mode":"rule"}, "/proxies": {"proxies":{}}, "/rules": {"rules":[]}}
        token = self.server.state.config.get("mihomoToken")
        if self.path not in allowed or self.headers.get("Authorization") != "Bearer " + str(token): self.send(403, b'{"message":"forbidden"}\n'); return
        self.send(200, C.canonical(allowed[self.path]))

def decode_name(packet, offset):
    labels=[]
    while True:
        if offset >= len(packet): raise Rejected()
        n=packet[offset]; offset+=1
        if n == 0: return ".".join(labels), offset
        if n > 63 or offset+n > len(packet): raise Rejected()
        labels.append(packet[offset:offset+n].decode("ascii")); offset += n

class DoT(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads=False; allow_reuse_address=False
    def __init__(self, address, context, state):
        self.state=state; super().__init__(address, DNSHandler, bind_and_activate=False)
        self.socket=context.wrap_socket(socket.socket(), server_side=True); self.server_bind(); self.server_activate()
class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        head=self.request.recv(2)
        if len(head)!=2:return
        size=struct.unpack("!H",head)[0]; packet=b""
        while len(packet)<size:
            part=self.request.recv(size-len(packet))
            if not part:return
            packet+=part
        response,name,known,answers,rcode=dns_response(packet)
        self.request.sendall(struct.pack("!H",len(response))+response)
        self.server.state.event("dot","response",reference=name,status=400 if rcode==5 else 200 if known else 404,bytes=len(response),connection="dot-"+str(self.request.fileno())+"-"+str(time.time_ns()),tlsClass="server_tls",authClass="not_applicable",responseClass="dns_refused" if rcode==5 else "dns_answer" if answers else "dns_nodata" if known else "dns_rejected")

def dns_response(packet):
    name,end=decode_name(packet,12); qtype,qclass=struct.unpack("!HH",packet[end:end+4]); question=packet[12:end+4]
    valid=qclass==1 and qtype in (1,28);known=name in C.SOURCE_HOSTS.values();answers=1 if valid and known and qtype==1 else 0
    # FixedDoTResolver asks both A and AAAA. A known name without AAAA is
    # NOERROR/NODATA; NXDOMAIN would invalidate the complete resolution.
    rcode=0 if valid and known else 3 if valid else 5;flags=0x8180|rcode
    answer=b"\xc0\x0c"+struct.pack("!HHIH",1,1,30,4)+socket.inet_aton(C.SOURCE_IP) if answers else b""
    return packet[:2]+struct.pack("!HHHHH",flags,1,answers,0,0)+question+answer,name,known,answers,rcode

def tls_context(cert, key):
    c=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); c.minimum_version=ssl.TLSVersion.TLSv1_2; c.load_cert_chain(cert,key); return c

def exclusive(path, value):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
    with os.fdopen(fd,"wb") as f: f.write(C.canonical(value)); f.flush(); os.fsync(f.fileno())

def serve(args):
    root=pathlib.Path(args.root).resolve(); config=read_json(root/"fixture-input.private.json"); state=State(root,config)
    servers=[DoT(C.DOT,tls_context(root/"resolver-cert.pem",root/"resolver-key.private.pem"),state),
             TLSHTTP(C.SOURCE,Handler,tls_context(root/"source-cert.pem",root/"source-key.private.pem"),state,"source"),
             TLSHTTP(C.MIHOMO,Handler,tls_context(root/"mihomo-cert.pem",root/"mihomo-key.private.pem"),state,"mihomo")]
    stop=threading.Event(); signal.signal(signal.SIGTERM,lambda *_:stop.set()); signal.signal(signal.SIGINT,lambda *_:stop.set())
    threads=[threading.Thread(target=s.serve_forever,daemon=False) for s in servers]
    for t in threads:t.start()
    exclusive(root/"fixture-ready.json",{"schema":C.READY_SCHEMA,"pid":os.getpid(),"uid":os.getuid(),"gid":os.getgid(),"listeners":["127.0.0.1:1853","8.8.4.4:443","8.8.4.4:9443"]})
    stop.wait(args.deadline_seconds)
    normal=stop.is_set()
    for s in servers:s.shutdown();s.server_close()
    for t in threads:t.join(5)
    exclusive(root/"fixture-stopped.json",{"schema":C.STOPPED_SCHEMA,"pid":os.getpid(),"normalStop":normal,"events":state.ordinal,"workerThreadsAlive":sum(t.is_alive() for t in threads),"listenersClosed":all(not t.is_alive() for t in threads)})
    return 0 if normal and all(not t.is_alive() for t in threads) else 1

def main():
    p=argparse.ArgumentParser(); p.add_argument("serve",nargs="?");p.add_argument("--root",required=True);p.add_argument("--deadline-seconds",type=int,default=180);a=p.parse_args()
    try:return serve(a)
    except Exception:return 1
if __name__=="__main__": raise SystemExit(main())
