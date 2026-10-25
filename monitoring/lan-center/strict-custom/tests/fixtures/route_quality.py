"""Business-specific, sticky routing; called only by the isolated probe scheduler.

No background probe thread: the capability evaluator owns the same probe listener.
The policy file is the activation switch. Native routing survives this process.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import statistics
import subprocess
import tempfile
import time
import urllib.parse
from autonomy_store import atomic_json, checkpoint, recover_document, exclusive, assess_window, valid_sample

ROOT = Path(os.getenv("QUALITY_STATE_DIR", "/data"))
POLICY = ROOT / "route-quality-policy.json"
STATE = ROOT / "route-quality.json"
BUSINESSES = {
    "gemini": ("🔵 Gemini 专用节点池", "🔵 对话助手（Gemini）"),
    "chatgpt": ("🤖 ChatGPT 专用节点池", "🤖 对话助手（ChatGPT）"),
    "default": ("🛡️ 稳定业务出口", "🔒 隐私代理"),
}
PROBES = {
    "gemini": [("https://generativelanguage.googleapis.com/$discovery/rest?version=v1beta", "GET", 200, "gemini")],
    "chatgpt": [("https://chatgpt.com/backend-api/codex/responses", "POST", 401, "json")],
    "default": [("https://www.gstatic.com/generate_204", "GET", 204, None),
                ("https://github.com/robots.txt", "GET", 200, "text")],
}
GEMINI_REGIONS = {"US", "JP", "SG", "TW", "KR", "GB", "DE"}
# Conservative local allowlist, not a claim that all other countries are unsupported.
REGION_GATED = {"gemini", "chatgpt"}


def region_allowed(node, now):
    observed = node.get("egress", {})
    return observed.get("country") in GEMINI_REGIONS and 0 <= now-observed.get("last_checked",0) <= 7200


def valid_state(value):
    if not isinstance(value, dict) or value.get("schema") != 1:
        return False
    if not all(isinstance(value.get(k), dict) for k in ("samples", "businesses")) or not isinstance(value.get("switches"), list):
        return False
    for samples in value["samples"].values():
        if not isinstance(samples, list): return False
        for s in samples:
            if not valid_sample(s):return False
    if not all(isinstance(info,dict) for info in value["businesses"].values()):return False
    for info in value["businesses"].values():
        if any(type(info.get(k,0)) not in (int,float) for k in ("bad_streak","last_switch")):return False
        if not isinstance(info.get("rejected_until",{}),dict):return False
        if any(type(t) not in (int,float) for t in info.get("rejected_until",{}).values()):return False
    for switch in value["switches"]:
        if not isinstance(switch,dict) or type(switch.get("at")) not in (int,float) or switch.get("business") not in BUSINESSES:return False
    job=value.get("trial")
    if job and (not isinstance(job,dict) or job.get("business") not in BUSINESSES or not isinstance(job.get("new"),str)):return False
    window=value.get("acceptance")
    if window and (not isinstance(window,dict) or type(window.get("started_at")) not in (int,float) or not isinstance(window.get("records"),dict)):return False
    if window:
        for rows in window["records"].values():
            if not isinstance(rows,list) or not all(valid_sample(row) for row in rows):return False
    return True


def valid_policy(value):
    return (isinstance(value,dict) and value.get("schema",1)==1 and type(value.get("enabled")) is bool
            and type(value.get("manual_override_seconds",0)) is int and 0<=value.get("manual_override_seconds",0)<=604800)


def metrics(samples, now):
    recent = [s for s in samples[-30:] if 0 <= now - s["at"] <= 1800]
    good = [s["ms"] for s in recent if s["ok"]]
    last = recent[-3:]
    recent_good = [s["ms"] for s in last if s["ok"]]
    return {
        "samples": len(recent), "success_ratio": sum(s["ok"] for s in recent) / len(recent) if recent else 0,
        "slow_ratio": sum(not s["ok"] or s["ms"] > 3000 for s in recent) / len(recent) if recent else 1,
        "median_ms": round(statistics.median(good)) if good else 8000,
        "recent_median_ms": round(statistics.median(recent_good)) if recent_good else 8000,
        "p95_ms": sorted(good)[min(len(good)-1, int(len(good)*.95))] if good else 8000,
        "hard_failure": len(last) >= 2 and all(not s["ok"] for s in last[-2:]),
        "eligible": len(last) == 3 and all(s["ok"] and s["ms"] < 3000 for s in last)
                    and now - last[-1]["at"] <= 300
                    and (len(recent)<5 or sum(s["ok"] for s in recent)/len(recent)>=.9),
    }


def should_switch(current, candidate, bad_streak, held_seconds):
    # One slow request never triggers a switch. A stale candidate never qualifies.
    return bool(candidate["eligible"] and bad_streak >= 2
                and (held_seconds >= 600 or current.get("hard_failure") or current["success_ratio"] == 0)
                and (current["slow_ratio"] >= .3 or current["success_ratio"] < .9)
                and (current["success_ratio"] < .9 or
                     candidate.get("recent_median_ms",candidate["median_ms"]) < current.get("recent_median_ms",current["median_ms"]) * .75))


def probe(business, production=False):
    durations = []
    for url, method, expected, hint in PROBES[business]:
        with tempfile.TemporaryDirectory() as directory:
            body = Path(directory) / "body"
            command = ["curl", "-sS", "--connect-timeout", "4", "--max-time", "8",
                       "--max-filesize", "2097152", "-x", os.environ["PROXY" if production else "CAPABILITY_PROXY"],
                       "-U", os.environ["PROXY_AUTH" if production else "CAPABILITY_PROXY_AUTH"], "-o", str(body),
                       "-w", "%{http_code}|%{time_total}|%{content_type}",
                       "-H", "User-Agent: lan-center-quality/1"]
            if method == "POST":
                command += ["-X", "POST", "-H", "Content-Type: application/json", "-d", "{}"]
            command.append(url)
            try:
                result = subprocess.run(command, capture_output=True, timeout=10)
                code, seconds, content = result.stdout.decode().split("|", 2)
                ms = round(float(seconds) * 1000)
                ok = result.returncode == 0 and int(code) == expected
                reason = "ok" if ok else "timeout" if result.returncode == 28 else "http_or_transport"
                if ok and hint in {"json", "gemini"}:
                    data = json.loads(body.read_text(encoding="utf-8"))
                    ok = "json" in content and isinstance(data, dict)
                    if hint == "gemini":
                        ok = ok and data.get("name") == "generativelanguage" and data.get("kind") == "discovery#restDescription"
                    if not ok: reason = "unexpected_content"
                elif ok and hint == "text":
                    ok = "text/plain" in content and "user-agent" in body.read_text(encoding="utf-8").lower()
                    if not ok: reason = "unexpected_content"
                durations.append(ms)
                if not ok: return {"ok": False, "ms": ms, "reason": reason, "http": code}
            except (ValueError, OSError, subprocess.TimeoutExpired):
                return {"ok": False, "ms": 8000, "reason": "probe_error", "http": "000"}
    return {"ok": True, "ms": max(durations), "reason": "ok", "http": str(expected)}


class Controller:
    def __init__(self, api, node_status, clock=time.time, probe_fn=probe, verify_fn=None):
        self.api, self.node_status, self.clock, self.probe_fn = api, node_status, clock, probe_fn
        self.verify_fn = verify_fn or (lambda b: probe(b, True) if probe_fn is probe else probe_fn(b))
        self.state_error = False
        self.state, recovered = recover_document(STATE,valid_state)
        if self.state is None:
            self.state = {"schema":1,"samples":{},"businesses":{},"switches":[]}
            recovered = "reconstructed_unqualified"
        self.state["recovery"] = recovered
        self.last_checkpoint = 0

    def save(self, detail="business_quality"):
        now = int(self.clock())
        self.state.update(epoch=now,detail=detail,controller_version="8.1")
        atomic_json(STATE,self.state)
        if now-self.last_checkpoint>=60:
            checkpoint(STATE,self.state)
            self.last_checkpoint=now

    def recover_trial(self):
        """Roll back only selections we still own. Never overwrite a manual change."""
        job=self.state.get("trial")
        if not job: return
        pool,outer=BUSINESSES[job["business"]]
        fresh=self.api("/proxies")["proxies"]
        if fresh.get(outer,{}).get("now")==pool and fresh.get(pool,{}).get("now")==job["new"]:
            old=job.get("old_pool")
            if old and old in fresh.get(pool,{}).get("all",[]): self.select(pool,old)
            else: raise RuntimeError("rollback_node_missing")
            old_outer=job.get("old_outer")
            if old_outer and old_outer in fresh.get(outer,{}).get("all",[]): self.select(outer,old_outer)
        self.state.pop("trial",None)
        self.save("trial_recovered")

    def switch(self,business,best,now):
        pool,outer=BUSINESSES[business]
        fresh=self.api("/proxies")["proxies"]
        if fresh.get(outer,{}).get("now")!=pool or best not in fresh.get(pool,{}).get("all",[]):return False
        info=self.state["businesses"][business]
        budget=[s for s in self.state["switches"] if s["business"]==business and 0<=now-s["at"]<600]
        if len(budget)>=2:
            info["phase"]="cooldown_switch_budget"; return False
        self.state["trial"]={"business":business,"new":best,"old_pool":fresh[pool].get("now"),"old_outer":pool,"at":now}
        self.save("trial_prepared")
        self.state["switches"].append({"at":now,"business":business,"node_hash":hashlib.sha256(best.encode()).hexdigest()[:12],"result":"trial"})
        del self.state["switches"][:-100]
        self.save("trial_started")
        try:
            self.select(pool,best)
            for _ in range(2):
                result=self.verify_fn(business)
                if not result["ok"] or result["ms"]>3000:raise RuntimeError("post_switch_probe_failed")
                if self.api("/proxies/"+urllib.parse.quote(outer,safe="")).get("now")!=pool:
                    raise RuntimeError("manual_override_during_trial")
            self.state.pop("trial",None)
            info.update(enrolled=True,last_switch=now,current=best,bad_streak=0,phase="stable",status="checking",latest_probe="post_switch_verified")
            self.state["switches"][-1]["result"]="committed"
            self.save("trial_committed")
            return True
        except Exception as error:
            self.state["switches"][-1]["result"]="rolled_back"
            self.state["switches"][-1]["reason"]=type(error).__name__
            info.setdefault("rejected_until",{})[best]=now+900
            self.recover_trial()
            info["phase"]="rollback_cooldown"
            self.save("trial_rolled_back")
            return False

    def select(self, group, node):
        path = "/proxies/" + urllib.parse.quote(group, safe="")
        before = self.api(path)
        if node not in before.get("all", []):
            raise RuntimeError("node_not_in_group")
        old = before.get("now")
        self.api(path, "PUT", {"name": node})
        if self.api(path).get("now") != node:
            if old: self.api(path, "PUT", {"name": old})
            raise RuntimeError("selection_readback_failed")
        return old

    @staticmethod
    def leaf(proxies, group):
        seen = set()
        while group in proxies and proxies[group].get("now"):
            if group in seen: raise ValueError("group_cycle")
            seen.add(group); group = proxies[group]["now"]
        return group

    def tick(self):
        with exclusive(STATE.parent/"routing-owner.lock") as acquired:
            if not acquired:
                self.save("publication_owns_routing");return False
            return self._tick()

    def _tick(self):
        now=int(self.clock())
        if (STATE.parent/"automation-freeze").exists():
            self.state["enabled"]=False;self.save("operator_freeze");return False
        try:
            policy=json.loads(POLICY.read_text(encoding="utf-8"))
            if not valid_policy(policy):raise ValueError("policy")
        except (OSError,ValueError,TypeError):
            self.state["enabled"]=False
            self.save("policy_invalid_frozen")
            return False
        self.state["enabled"]=policy["enabled"]
        if self.state.get("trial"):self.recover_trial()
        self.save("checking")
        proxies = self.api("/proxies")["proxies"]
        nodes = sorted(self.node_status()["nodes"], key=lambda n: -n["score"])
        nodes = [n for n in nodes if n.get("general_success_ratio", 0) >= .8]
        pending = []
        for business, (pool, outer) in BUSINESSES.items():
            if proxies.get(pool, {}).get("type") != "Selector": continue
            current = self.leaf(proxies, outer)
            # A user selection outside the managed pool is respected after initial enrollment.
            info = self.state["businesses"].setdefault(business, {"bad_streak": 0, "last_switch": 0})
            manual = proxies.get(outer, {}).get("now") != pool
            if manual:
                selected=proxies.get(outer,{}).get("now")
                if selected!=info.get("manual_selection"):
                    info.update(manual_selection=selected,manual_since=now)
                lease=policy.get("manual_override_seconds",0)
                if lease and now-info.get("manual_since",now)>=lease and policy["enabled"]:
                    if self.api("/proxies/"+urllib.parse.quote(outer,safe="")).get("now")==selected:
                        self.select(outer,pool); manual=False; current=self.leaf(proxies,pool)
            else:
                info.pop("manual_selection",None);info.pop("manual_since",None)
            allowed = set(proxies[pool].get("all", []))
            if business in REGION_GATED:
                # A public discovery document returning 200 does not prove service region eligibility.
                allowed &= {n["name"] for n in nodes if region_allowed(n,now)}
            candidates = []
            providers = set()
            for n in nodes:
                cap = n.get("capabilities", {}).get(business if business != "default" else "general", {})
                if n["name"] not in allowed or cap.get("status") != "available": continue
                if n.get("provider") not in providers:
                    candidates.append(n["name"]);providers.add(n.get("provider"))
                if len(candidates) == 2:break
            # Add geographic diversity, including never-qualified nodes for isolated
            # testing. A stale coarse capability label cannot permanently hide a spare.
            node_regions={n["name"]:n.get("egress",{}).get("country","unknown") for n in nodes}
            regions = {node_regions.get(n,"unknown") for n in candidates}
            for n in nodes:
                if n["name"] not in allowed or n["name"] in candidates:continue
                if node_regions[n["name"]] not in regions:
                    candidates.append(n["name"]);regions.add(node_regions[n["name"]])
                if len(candidates) >= 4:break
            if len(candidates) < 4:
                candidates += [n["name"] for n in nodes if n["name"] in allowed and n["name"] not in candidates][:4-len(candidates)]
            # Provider nodes need not appear in /proxies. Pool membership is authoritative.
            if current in proxies[pool].get("all",[]) and current not in candidates:candidates.append(current)
            info.update(current=current, manual_override=bool(manual), candidates=candidates)
            for name in candidates:
                key = business + ":" + hashlib.sha256(name.encode()).hexdigest()[:16]
                samples = self.state["samples"].get(key, [])
                m = metrics(samples, now)
                interval = 5 if not m["eligible"] and len(samples) < 3 else 120 if name == current else 300
                if samples and samples[-1].get("http") in {"403", "429"} and name != current:
                    interval = 900
                last = samples[-1]["at"] if samples else 0
                if now-last >= interval:
                    pending.append((0 if name==current else 1 if len(samples)<3 else 2,last,business,name,key))
        if not pending:
            self.save("idle")
            return False
        _, _, business, name, key = min(pending)
        probe_group = os.getenv("CAPABILITY_GROUP", "🧪 节点能力检测")
        old_probe = self.select(probe_group, name)
        try:
            time.sleep(float(os.getenv("QUALITY_SETTLE_SECONDS", ".3")))
            sample = self.probe_fn(business)
        finally:
            # Do not restore a removed subscription node or clobber an external selection.
            latest = self.api("/proxies/" + urllib.parse.quote(probe_group, safe=""))
            if latest.get("now") != name:
                sample = {"ok": False, "ms": 8000, "reason": "probe_group_changed", "http": "000"}
            if latest.get("now") == name and old_probe in latest.get("all", []):self.select(probe_group, old_probe)
        now = int(self.clock());sample["at"] = now
        samples = self.state["samples"].setdefault(key, [])
        samples.append(sample);del samples[:-30]
        info = self.state["businesses"][business]
        m = metrics(samples, now)
        if name == info["current"]:
            info["bad_streak"] = info.get("bad_streak", 0)+1 if not sample["ok"] or sample["ms"] > 3000 else 0
            info["metrics"] = m
            info["latest_probe"] = "ok" if sample["ok"] else "failed"
            info["status"] = ("down" if m["hard_failure"] else "checking" if not sample["ok"]
                              else "slow" if m["slow_ratio"]>.05 or m["success_ratio"]<.99 else "normal")
            info["assurance"] = "transport_and_observed_region" if business in REGION_GATED else "unauthenticated_transport"
            if policy.get("enabled") and info.get("enrolled") and not info.get("manual_override"):
                window=self.state.setdefault("acceptance",{"started_at":now,"records":{},"status":"running"})
                # Keep the previous observation intact, and start a versioned window.
                if now-window["started_at"]<=86400:
                    window["records"].setdefault(business,[]).append(sample)
                verdict=assess_window(window["records"],window["started_at"],now)
                window.update(verdict)
                if window["status"] in {"passed","failed"}:
                    self.state["last_acceptance"]={k:v for k,v in window.items() if k!="records"}
                    if window["status"]=="passed":checkpoint(STATE.parent/"quality-accepted.json",self.state["last_acceptance"])
                    self.state["acceptance"]={"started_at":now,"records":{},"status":"running"}
        if policy.get("enabled") and not info.get("manual_override"):
            allowed=set(proxies.get(BUSINESSES[business][0],{}).get("all",[]))
            if business in REGION_GATED:allowed&={n["name"] for n in nodes if region_allowed(n,now)}
            choices = []
            for candidate in info["candidates"]:
                k = business + ":" + hashlib.sha256(candidate.encode()).hexdigest()[:16]
                cm = metrics(self.state["samples"].get(k, []), now)
                if candidate in allowed and cm["eligible"] and info.get("rejected_until",{}).get(candidate,0)<=now:
                    choices.append((cm["recent_median_ms"],candidate,cm))
            if choices:
                _, best, bm = min(choices)
                current_key=business+":"+hashlib.sha256(info["current"].encode()).hexdigest()[:16]
                current=metrics(self.state["samples"].get(current_key,[]),now)
                initial = not info.get("enrolled")
                if initial or (best != info["current"] and should_switch(current,bm,info.get("bad_streak",0),now-info.get("last_switch",0))):
                    if self.switch(business,best,now):info.update(metrics=bm)
            elif info.get("bad_streak",0)>=2:
                info["phase"]="degraded_no_qualified_spare"
        self.state.update(epoch=now,enabled=bool(policy.get("enabled")),detail="business_quality")
        # Bound historical state across subscription churn and renamed nodes.
        active_keys = set()
        for b, item in self.state["businesses"].items():
            active_keys.update(b+":"+hashlib.sha256(n.encode()).hexdigest()[:16] for n in item.get("candidates",[]))
        self.state["samples"] = {k:v for k,v in self.state["samples"].items() if k in active_keys}
        self.save()
        return True
