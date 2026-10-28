#!/usr/bin/env python3
"""Offline domain-stage simulation of generated OpenClash rule order."""
import argparse,gzip,hashlib,json,re
from collections import Counter
from pathlib import Path
from build_routing_samples import matches,patterns
ROOT=Path(__file__).resolve().parents[1];CORPUS=ROOT/"tests/routing_samples.jsonl"
MANIFEST=ROOT/"tests/routing_snapshot_manifest.json";EVIDENCE=ROOT/"reports/routing-sample-audit.json"
REPORT=ROOT/"docs/routing-sample-audit-20261028.md"
TARGET_ROOT=ROOT
PACK=ROOT/"tests/routing-sources/snapshots.json.gz"

def local_patterns(path,classical=False):
 text=path.read_text(encoding="utf-8")
 if classical:
  text="\n".join(line for line in text.splitlines() if re.search(r"-\s+['\"]?DOMAIN(?:,|-SUFFIX,|-KEYWORD,|-WILDCARD,|-REGEX,)",line,re.I))
 rule,unsupported=patterns(text)
 if unsupported:raise RuntimeError(f"unsupported local domain rules: {path.name}={unsupported}")
 return rule

def domain_match(domain,rule):return matches(rule,domain)

def ordered_rules():
 rules=[]
 for number,raw in enumerate((TARGET_ROOT/"metafenliu.ini").read_text(encoding="utf-8").splitlines(),1):
  if not raw.startswith("ruleset="):continue
  target,spec=raw[len("ruleset="):].split(",",1)
  if spec=="[]FINAL":rules.append((number,target,"final",None));continue
  match=re.match(r"\[\](DOMAIN|DOMAIN-SUFFIX|DOMAIN-KEYWORD|DOMAIN-WILDCARD|DOMAIN-REGEX),(.+)$",spec)
  if match:rules.append((number,target,match.group(1).lower(),match.group(2).lower()));continue
  match=re.match(r"\[\]GEOSITE,([^,]+)$",spec)
  if match:rules.append((number,target,"membership",match.group(1)));continue
  if "Custom_Direct_Domain.yaml" in spec:rules.append((number,target,"membership","external-direct"));continue
  if "Custom_Proxy_Domain.yaml" in spec:rules.append((number,target,"membership","external-proxy"));continue
  match=re.search(r"/rules/([^,/?]+\.yaml)",spec)
  if match and (TARGET_ROOT/"rules"/match.group(1)).is_file():
   kind="local-classic" if "clash-classic:" in spec else "local-domain"
   rules.append((number,target,kind,match.group(1)));continue
  if spec.startswith(("[]GEOIP,","[]IP-CIDR,","[]IP-CIDR6,","clash-classic:")):continue
  raise RuntimeError(f"unsupported domain-stage rule at line {number}: {spec.split(':',1)[0]}")
 return rules

def simulate(row,rules,cache):
 domain=row["domain"];members=set(row["memberships"])
 for number,target,kind,value in rules:
  hit=kind=="final" or (kind=="domain" and domain==value) or (kind=="domain-suffix" and (domain==value or domain.endswith("."+value))) or (kind=="domain-keyword" and value in domain) or (kind=="membership" and value in members)
  if kind=="domain-wildcard":hit=bool(re.fullmatch(re.escape(value).replace(r"\*",".*"),domain,re.I))
  if kind=="domain-regex":hit=bool(re.search(value,domain,re.I))
  if kind in {"local-domain","local-classic"}:
   key=(kind,value)
   if key not in cache:cache[key]=local_patterns(TARGET_ROOT/"rules"/value,kind=="local-classic")
   hit=domain_match(domain,cache[key])
  if hit:return {"actual":target,"rule_line":number,"rule_kind":kind,"rule_source":value}
 return {"actual":"UNKNOWN","rule_line":None,"rule_kind":"unknown","rule_source":None}

def mismatch_class(row,actual):
 if row["expected"]==actual:return "matched"
 if row["family"]=="proxy-required-policy" and actual=="DIRECT":return "需代理政策域名却命中 DIRECT"
 if row["expected"]=="DIRECT" and actual!="DIRECT":return "国内策略域名却进入非 DIRECT 目标"
 if row["family"] in {"business","game","streaming","finance","cdn"} and actual!=row["expected"]:return "应走业务组却被抢先"
 return "其他错配"

def hierarchy_review(expected,actual):
 pairs={("🛠️ 代码托管（GitHub）","🧑‍💻 编程助手（GitHub Copilot）"),
        ("🧠 人工智能","🔵 对话助手（Gemini）"),("🧠 人工智能","🟠 对话助手（Claude）"),
        ("🧠 人工智能","⚫ 对话助手（Grok）"),("🎮 游戏平台（Steam）","⬇️ 游戏下载"),
        ("🟣 游戏平台（Epic）","⬇️ 游戏下载")}
 return (expected,actual) in pairs

def frozen_sources(manifest):
 if hashlib.sha256(PACK.read_bytes()).hexdigest()!=manifest["snapshot_pack_sha256"]:raise SystemExit("snapshot pack hash mismatch")
 packed=json.loads(gzip.decompress(PACK.read_bytes()).decode("utf-8"));expected={row["name"]:row for row in manifest["sources"]}
 if set(packed)!=set(expected):raise SystemExit("snapshot source set mismatch")
 loaded={}
 for name,source in packed.items():
  meta=expected[name];raw=source["text"].encode()
  if meta["status"]!="loaded" or not meta.get("revision") or hashlib.sha256(raw).hexdigest()!=meta["sha256"]:
   raise SystemExit("snapshot source mismatch: "+name)
  rule,unsupported=patterns(source["text"]);entries=sum(len(rule[key]) for key in ("exact","suffix","keyword","regex"))
  if unsupported or unsupported!=meta["unsupported_entries"] or entries!=meta["entries"]:
   raise SystemExit("snapshot semantics mismatch: "+name)
  loaded[name]=rule
 return loaded

def run(write=False):
 rows=[json.loads(x) for x in CORPUS.read_text(encoding="utf-8").splitlines() if x]
 manifest=json.loads(MANIFEST.read_text(encoding="utf-8"))
 if hashlib.sha256(CORPUS.read_bytes()).hexdigest()!=manifest["corpus_sha256"]:raise SystemExit("corpus hash mismatch")
 loaded=frozen_sources(manifest)
 for row in rows:
  calculated=sorted(name for name,rule in loaded.items() if matches(rule,row["domain"]))
  if calculated!=row["memberships"]:raise SystemExit("materialized membership mismatch: "+row["domain"])
 rules=ordered_rules();required={value for _,_,kind,value in rules if kind=="membership"}
 if not required.issubset(loaded):raise SystemExit("template membership missing from snapshot: "+", ".join(sorted(required-set(loaded))))
 cache={};results=[]
 for row in rows:
  result=simulate(row,rules,cache);result.update({k:row[k] for k in ("domain","expected","family","seed_source","memberships","policy_review")})
  result["policy_review"]=result["policy_review"] or hierarchy_review(result["expected"],result["actual"])
  result["classification"]=mismatch_class(row,result["actual"]);results.append(result)
 strict=[r for r in results if not r["policy_review"]];matched=sum(r["classification"]=="matched" for r in strict)
 review=[r for r in results if r["policy_review"]];anchors=[r for r in results if r["seed_source"]=="user-policy"]
 category_counts=Counter(r["classification"] for r in results)
 for name in ("需代理政策域名却命中 DIRECT","国内策略域名却进入非 DIRECT 目标","应走业务组却被抢先","其他错配"):category_counts.setdefault(name,0)
 summary={"schema":2,"domain_stage_only":True,"samples":len(results),"strict_samples":len(strict),"matched":matched,
  "policy_review":len(review),"policy_review_matched":sum(r["expected"]==r["actual"] for r in review),
  "policy_review_mismatched":sum(r["expected"]!=r["actual"] for r in review),"unknown":sum(r["actual"]=="UNKNOWN" for r in strict),
  "human_policy_anchors":len(anchors),"human_policy_anchors_matched":sum(r["expected"]==r["actual"] for r in anchors),
  "categories":dict(category_counts),"policy_oracle_consistency_percent":round(100*matched/len(strict),3),
  "source_snapshot":{s["name"]:{k:s.get(k) for k in ("revision","sha256","status")} for s in manifest["sources"]}}
 evidence={"summary":summary,"mismatches":[r for r in results if r["expected"]!=r["actual"]]}
 if write:
  EVIDENCE.parent.mkdir(exist_ok=True);EVIDENCE.write_text(json.dumps(evidence,ensure_ascii=False,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  categories=category_counts;anchors={r["domain"]:r for r in results if r["seed_source"]=="user-policy"}
  lines=["# 分流样本离线审计（2026-10-28）","",f"- 样本：{len(results)} 条唯一上游规则域名样本；严格计分 {len(strict)} 条；政策待确认 {summary['policy_review']} 条。",
   f"- 严格计分集的政策一致率：{matched}/{len(strict)} = {summary['policy_oracle_consistency_percent']}%。期望大多由固定分类快照和仓库政策映射推导，并非独立网络事实。",
   f"- 人工政策锚点：{summary['human_policy_anchors_matched']}/{summary['human_policy_anchors']}；政策待确认样本中实际一致 {summary['policy_review_matched']}、不一致 {summary['policy_review_mismatched']}。",
   "- 模拟边界：固定上游快照、仅域名匹配；不连接设备，不覆盖 IP、端口、进程或复杂 classical 条件，也不声称实时网络封锁状态。",
   "- `actual` 是规则首次命中的目标策略组，不是该组当前选择的节点或实际出口；本审计没有读取运行时选择。",
   "- 完整错配、首个命中规则及来源成员关系见 `reports/routing-sample-audit.json`。","","## 错配分类",""]
  lines += [f"- {name}：{count}" for name,count in sorted(categories.items()) if name!="matched"]
  lines += ["","## 已知政策锚点",""]
  for domain in sorted(anchors):
   row=anchors[domain];lines.append(f"- `{domain}`：期望 `{row['expected']}`，实际 `{row['actual']}`，首命中第 {row['rule_line']} 行 `{row['rule_source']}`。")
  lines += ["","## 修复清单","","### 可在现有规则文件修复","",
   "- `hhyunerp.com` 及子域当前落入 FINAL；有独立用户政策证据，可在既有 `rules/direct.yaml` 用一个后缀条目修复。",
   "","### 需要模板或顺序另行授权","",
   "- `fonts.googleapis.com` 被更早 `google-cn` 命中，`iq.com` 被更早第三方直连命中；修改后置规则文件不能覆盖。",
   f"- 业务组被抢先共 {categories['应走业务组却被抢先']} 条；完整域名、期望、实际目标及首命中规则在 JSON 中，不能机械加入后置规则。",
   "- 游戏被海外影音抢先需要修改运行配置模板；本次仅记录，未经单独批准不修改。",
   "","### 需要用户决定","",
   f"- 政策冲突待确认 {summary['policy_review']} 条，其中目标不一致 {summary['policy_review_mismatched']} 条；广告与业务、国内分类与海外业务等重叠不自动视为代码缺陷。",
   f"- 国内政策非 DIRECT 目标共 {categories['国内策略域名却进入非 DIRECT 目标']} 条；除已有独立政策证据外不自动加入直连。",
   "- DNS 覆写键属于设备配置问题，本次仅记录，未经单独批准不修改。"]
  REPORT.write_text("\n".join(lines)+"\n",encoding="utf-8")
 print(json.dumps(summary,ensure_ascii=False,sort_keys=True));return summary,results

if __name__=="__main__":
 parser=argparse.ArgumentParser();parser.add_argument("--write",action="store_true");parser.add_argument("--config-root",type=Path)
 args=parser.parse_args()
 if args.config_root:TARGET_ROOT=args.config_root.resolve()
 run(args.write)
