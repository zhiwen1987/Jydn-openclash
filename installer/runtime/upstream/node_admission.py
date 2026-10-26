"""Bounded onboarding of unseen nodes in an ephemeral loopback-only core.

Never inserts an untested node into the production provider just to test it.
The pinned core is copied from the live router during an approved deployment.
"""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
import uuid

import yaml

CORE=Path(os.getenv("ADMISSION_CORE","/opt/mihomo-validate"))
PIN=Path(os.getenv("ADMISSION_CORE_PIN","/opt/mihomo-validate.sha256"))
TYPES={"ss","ssr","vmess","vless","trojan","hysteria","hysteria2","tuic","wireguard","socks5","http","anytls","ssh","mieru","snell"}


def isolated_config(node,port):
    if str(node.get("type","")).lower() not in TYPES:raise ValueError("unsupported_node_type")
    copy=dict(node);copy["name"]="admission-candidate"
    return {"mixed-port":port,"allow-lan":False,"bind-address":"127.0.0.1","mode":"rule","ipv6":False,
            "log-level":"silent","external-controller":"","profile":{"store-selected":False,"store-fake-ip":False},
            "dns":{"enable":False},"proxies":[copy],"proxy-groups":[],"rules":["MATCH,admission-candidate"]}


def resolve_public(name):
    api=os.getenv("OPENCLASH_API","").rstrip("/");secret=os.getenv("OPENCLASH_SECRET","")
    if not api or not secret:raise ValueError("bootstrap_resolver_credentials_missing")
    request=urllib.request.Request(api+"/dns/query?name="+urllib.parse.quote(name,safe="")+"&type=A",
                                   headers={"Authorization":"Bearer "+secret})
    with urllib.request.urlopen(request,timeout=5) as response:answers=json.loads(response.read())
    addresses=[]
    for item in answers.get("Answer",[]):
        try:address=ipaddress.ip_address(item.get("data",""))
        except ValueError:continue
        if address.version==4 and address.is_global:addresses.append(str(address))
    if not addresses:raise ValueError("bootstrap_resolver_no_public_answer")
    return addresses


def validate_native(node):
    try:
        isolated_config(node,17896)  # shared type/structure check before transport
        server=str(node.get("server",""))
        try:
            if not ipaddress.ip_address(server).is_global:return False,"server_address_not_public"
            hosts={}
        except ValueError:hosts={server:resolve_public(server)}
        for target in ("www.gstatic.com","cp.cloudflare.com"):hosts[target]=resolve_public(target)
        key=Path(os.getenv("ADMISSION_SSH_KEY","/data/admission-key"))
        known=Path(os.getenv("ADMISSION_KNOWN_HOSTS","/data/admission-known_hosts"))
        if not key.is_file() or not known.is_file():return False,"restricted_ssh_not_configured"
        payload=yaml.safe_dump({"node":node,"hosts":hosts,"token":uuid.uuid4().hex},allow_unicode=True)
        result=subprocess.run(["ssh","-i",str(key),"-o","IdentitiesOnly=yes","-o","BatchMode=yes",
                               "-o","StrictHostKeyChecking=yes","-o","UserKnownHostsFile="+str(known),
                               "-o","ConnectTimeout=5","root@10.88.0.254","validate-v1"],
                              input=payload,capture_output=True,text=True,timeout=75)
        if result.returncode:return False,"native_ssh_failed"
        document=json.loads(result.stdout[:1024])
        return document.get("ok") is True,str(document.get("reason","native_no_reason"))[:100]
    except Exception as error:return False,"native_admission_"+type(error).__name__


def validate(node):
    if os.getenv("ADMISSION_NATIVE_SSH","0")=="1":return validate_native(node)
    process=None
    try:
        if hashlib.sha256(CORE.read_bytes()).hexdigest()!=PIN.read_text().strip():return False,"core_pin_mismatch"
        with socket.socket() as port_socket:
            port_socket.bind(("127.0.0.1",0));port=port_socket.getsockname()[1]
        config=isolated_config(node,port)
        diagnostic=os.getenv("ADMISSION_DIAGNOSTIC","0")=="1"
        if diagnostic:config["log-level"]="warning"
        server=str(node.get("server",""))
        try:
            address=ipaddress.ip_address(server)
            if not address.is_global:return False,"server_address_not_public"
        except ValueError:
            # OS DNS may return a fake-IP. Use the router's actual resolver API,
            # preserving the original hostname/SNI and existing DNS policy.
            config["hosts"]={server:resolve_public(server)}
        for target in ("www.gstatic.com","cp.cloudflare.com"):
            config.setdefault("hosts",{})[target]=resolve_public(target)
        with tempfile.TemporaryDirectory(prefix="node-admission-") as directory:
            path=Path(directory)/"config.yaml"
            path.write_text(yaml.safe_dump(config,allow_unicode=True),encoding="utf-8");os.chmod(path,0o600)
            command=[str(CORE),"-d",directory,"-f",str(path)]
            result=subprocess.run(command+["-t"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
            if result.returncode:return False,"core_validation_failed"
            diagnostic_path=Path(directory)/"diagnostic.log"
            with open(diagnostic_path,"wb") as log:
                process=subprocess.Popen(command,stdout=log if diagnostic else subprocess.DEVNULL,stderr=subprocess.STDOUT)
            ready=False
            for _ in range(40):
                if process.poll() is not None:return False,"isolated_core_exited"
                try:
                    with socket.create_connection(("127.0.0.1",port),timeout=.1):ready=True;break
                except OSError:time.sleep(.1)
            if not ready:return False,"isolated_core_not_ready"
            for url in ("https://www.gstatic.com/generate_204","https://cp.cloudflare.com/generate_204"):
                result=subprocess.run(["curl","-sS","-o","/dev/null","-w","%{http_code}","--connect-timeout","6",
                                       "--max-time","12","-x",f"http://127.0.0.1:{port}",url],
                                      capture_output=True,text=True,timeout=14)
                if result.returncode or result.stdout.strip()!="204":
                    detail=""
                    if diagnostic:
                        text=diagnostic_path.read_text(errors="replace").lower()[:16000]
                        detail=":"+",".join(k for k in ("x509","certificate","authentication","tls","timeout","connection refused","no such host","deadline") if k in text)
                    return False,f"isolated_transport_failed:curl{result.returncode}:http{result.stdout.strip()[:3]}"+detail
            return True,"isolated_two_endpoints_passed"
    except Exception as error:return False,"admission_"+type(error).__name__
    finally:
        if process is not None:
            process.terminate()
            try:process.wait(timeout=3)
            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=3)
