#!/usr/bin/env python3
"""Rebuild the corpus from immutable public rule snapshots (networked tool)."""
from __future__ import annotations
import gzip, hashlib, io, json, re, urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/"tests/routing_samples.jsonl"; MANIFEST=ROOT/"tests/routing_snapshot_manifest.json"
PACK=ROOT/"tests/routing-sources/snapshots.json.gz"
META_REV="9f2b7462c7508ad85a1137e70d502b783c89794d"
AETHER_REV="ce364895f9b55317159b43c0397788933f0f8448"
META_BASE=f"https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/{META_REV}/geo/geosite"
AETHER_BASE=f"https://raw.githubusercontent.com/Aethersailor/Custom_OpenClash_Rules/{AETHER_REV}/rule"
SEED_QUOTAS={"geolocation-cn":420,"gfw":420,"category-ads-all":380,"category-games":300,
 "category-entertainment":300,"category-finance":220,"cloudflare":180,"google":160,
 "github":140,"openai":100,"youtube":100,"netflix":80,"paypal":60,"wise":50}
SPECIFIC=[("openai","🤖 对话助手（ChatGPT）","business"),("youtube","🎬 视频平台（YouTube）","business"),
 ("netflix","🎥 流媒体（Netflix）","business"),("tiktok","🎵 短视频（TikTok）","business"),
 ("disney","🏰 流媒体（Disney+）","business"),("hbo","📺 流媒体（HBO）","business"),
 ("primevideo","📦 流媒体（Prime Video）","business"),("twitch","🎥 直播平台（Twitch）","business"),
 ("spotify","🎧 音乐服务（Spotify）","business"),("github","🛠️ 代码托管（GitHub）","business"),
 ("steam","🎮 游戏平台（Steam）","business"),("epicgames","🟣 游戏平台（Epic）","business"),
 ("xbox","🟩 游戏平台（Xbox）","business"),("playstation","🔷 游戏平台（PlayStation）","business"),
 ("nintendo","🔴 游戏平台（Nintendo）","business"),("paypal","💳 支付服务（PayPal）","business"),
 ("wise","💸 跨境汇款（Wise）","business"),("okx","🟦 欧易（OKX）","business"),
 ("binance","🟨 币安（Binance）","business"),("bybit","🟪 交易平台（Bybit）","business"),
 ("notion","📦 笔记协作（Notion）","business"),("category-ai-!cn","🧠 人工智能","business"),
 ("telegram","📨 电报通讯（Telegram）","business"),("discord","💬 聊天社区（Discord）","business"),
 ("whatsapp","🟢 通讯工具（WhatsApp）","business"),("signal","🔐 安全通信（Signal）","business"),
 ("line","🟩 通讯工具（LINE）","business"),("category-communication","📞 即时通讯","business"),
 ("instagram","📸 图片社交（Instagram）","business"),("twitter","🐦 社交平台（X）","business"),
 ("facebook","👥 社交平台（Facebook）","business"),("reddit","🗨️ 社区论坛（Reddit）","business"),
 ("category-social-media-!cn","💬 社交平台","business"),("gitlab","🦊 代码托管（GitLab）","business"),
 ("docker","🐳 容器服务（Docker）","business"),("npmjs","📦 软件包服务（NPM）","business"),
 ("category-dev","💻 开发服务","business"),("category-speedtest","🚝 测速工具","business"),
 ("apple","🍎 苹果服务（Apple）","business"),("onedrive","☁️ 微软云盘（OneDrive）","business"),
 ("dropbox","📦 云存储（Dropbox）","business"),("microsoft","🪟 微软服务（Microsoft）","business"),
 ("category-scholar-!cn","📚 海外学术","business"),("category-ecommerce","🛒 海外电商","business"),
 ("google","🔎 谷歌服务（Google）","business"),("cloudflare","☁️ 网络服务（Cloudflare）","cdn")]
POLICY_ANCHORS={"fonts.googleapis.com":("🔎 谷歌服务（Google）","business"),
 "iq.com":("🎞️ 海外影音","streaming"),"hhyunerp.com":("DIRECT","domestic"),
 "www.hhyunerp.com":("DIRECT","domestic"),"snssdk.com":("DIRECT","domestic"),
 "mmstat.com":("DIRECT","domestic"),"futunn.com":("DIRECT","domestic"),"spdb.com":("DIRECT","domestic"),
 "moomoo.com":("🌍 境外网站","business"),"sysceo.com":("DIRECT","domestic"),
 "drvceo.com":("DIRECT","domestic"),"amd.com":("DIRECT","domestic"),
 "developer.amd.com.cn":("DIRECT","domestic"),"6wz.net":("DIRECT","domestic"),
 "kefu.me":("DIRECT","domestic"),"52ojk.com":("DIRECT","domestic"),"lla8.com":("DIRECT","domestic"),
 "6ta.net":("DIRECT","domestic")}

def fetch(url):
 request=urllib.request.Request(url,headers={"User-Agent":"Jydn-routing-corpus/1"})
 with urllib.request.urlopen(request,timeout=30) as response:raw=response.read()
 return raw.decode("utf-8"),hashlib.sha256(raw).hexdigest()

def patterns(text):
 result={"exact":set(),"suffix":set(),"keyword":set(),"regex":[]}; unsupported=0
 for raw in text.splitlines():
  match=re.match(r"^\s*-\s+(.+?)\s*$",raw)
  if not match:continue
  value=match.group(1).split(" #",1)[0].strip().strip("'\"").lower().rstrip(".")
  if value.startswith("+."):result["suffix"].add(value[2:]);continue
  if value.startswith("domain-suffix,"):result["suffix"].add(value.split(",",2)[1]);continue
  if value.startswith("domain,"):result["exact"].add(value.split(",",2)[1]);continue
  if value.startswith("domain-keyword,"):result["keyword"].add(value.split(",",2)[1]);continue
  if value.startswith("domain-wildcard,"):
   wildcard=value.split(",",2)[1]
   result["regex"].append(re.compile("^"+re.escape(wildcard).replace(r"\*",".*")+"$",re.I));continue
  if value.startswith("domain-regex,"):
   try:result["regex"].append(re.compile(value.split(",",1)[1],re.I))
   except re.error:unsupported+=1
   continue
  if value.startswith("keyword:"):result["keyword"].add(value[8:]);continue
  if value.startswith("regexp:"):
   try:result["regex"].append(re.compile(value[7:],re.I))
   except re.error:unsupported+=1
   continue
  if "*" in value and "," not in value:
   result["regex"].append(re.compile("^"+re.escape(value).replace(r"\*",".*")+"$",re.I));continue
  if "*" in value or "," in value:unsupported+=1;continue
  if re.fullmatch(r"[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?",value) and "." in value:result["exact"].add(value)
  else:unsupported+=1
 return result,unsupported

def matches(rule,domain):
 if domain in rule["exact"]:return True
 labels=domain.split(".")
 if any(".".join(labels[i:]) in rule["suffix"] for i in range(len(labels)-1)):return True
 if any(word in domain for word in rule["keyword"]):return True
 return any(expr.search(domain) for expr in rule["regex"])

def expectation(tags,domain):
 if domain in POLICY_ANCHORS:return (*POLICY_ANCHORS[domain],False)
 smart={"tuya.com","tuyacn.com","tuyaus.com","tuyaeu.com","tuyain.com"}
 if any(domain==s or domain.endswith("."+s) for s in smart):return "DIRECT","domestic",False
 broad={"category-ads-all","gfw","geolocation-!cn","geolocation-cn","cn"}
 review=("category-ads-all" in tags and (domain.endswith(".cn") or bool(tags-broad))) or ("external-direct" in tags and bool(tags&{"gfw","geolocation-!cn"}))
 if "category-ads-all" in tags:return "REJECT","advertising",review
 if domain.endswith(".cn"):
  return "DIRECT","domestic",bool(tags&{"gfw","category-entertainment","category-games","category-finance"})
 direct={"google-cn","apple-cn","microsoft@cn","steam@cn","category-games@cn","cn","geolocation-cn"}
 if tags&direct:
  routed={x[0] for x in SPECIFIC}|{"category-games","category-entertainment","category-finance","gfw","geolocation-!cn"}
  return "DIRECT","domestic",bool(tags&routed)
 for name,route,family in SPECIFIC:
  if name in tags:return route,family,review
 if "category-game-platforms-download" in tags:return "⬇️ 游戏下载","game",review
 if "category-games" in tags:return "🕹️ 游戏服务","game",review
 if "category-entertainment" in tags:return "🎞️ 海外影音","streaming",review
 if "category-finance" in tags:return "💳 海外支付","finance",review
 if "gfw" in tags:return "🔒 隐私代理","proxy-required-policy",review
 if "geolocation-!cn" in tags:return "🌐 默认策略","proxy",review
 return "UNKNOWN","unclassified",review

def write_corpus(rows,path):
 path.parent.mkdir(parents=True,exist_ok=True)
 path.write_text("".join(json.dumps(row,ensure_ascii=False,sort_keys=True)+"\n" for row in rows),encoding="utf-8",newline="\n")

def main():
 config=(ROOT/"metafenliu.ini").read_text(encoding="utf-8")
 categories=set(re.findall(r"\[\]GEOSITE,([^\r\n,]+)",config))|set(SEED_QUOTAS)|{x[0] for x in SPECIFIC}
 jobs={name:f"{META_BASE}/{name}.yaml" for name in categories}
 jobs.update({"external-direct":f"{AETHER_BASE}/Custom_Direct_Domain.yaml",
              "external-proxy":f"{AETHER_BASE}/Custom_Proxy_Domain.yaml"})
 loaded={};raw_sources={};failures=[];manifest={"schema":3,"notes":["Pinned public snapshots; not the database installed on any router.",
  "gfw is a source-list policy label, not a live reachability measurement.",
  "Domain-only audit: IP, port, process and complex classical rules are outside coverage."],"sources":[]}
 with ThreadPoolExecutor(max_workers=12) as pool:
  futures={pool.submit(fetch,url):name for name,url in jobs.items()}
  for future in as_completed(futures):
   name=futures[future]
   try:text,digest=future.result();rule,unsupported=patterns(text);loaded[name]=rule
   except Exception as error:
    manifest["sources"].append({"name":name,"revision":META_REV if name in categories else AETHER_REV,
      "status":"unsupported","error":type(error).__name__});failures.append(name);continue
   if unsupported:failures.append(name)
   raw_sources[name]={"revision":META_REV if name in categories else AETHER_REV,"text":text,"sha256":digest,"url":jobs[name]}
   entries=sum(len(rule[k]) for k in ("exact","suffix","keyword","regex"))
   manifest["sources"].append({"name":name,"revision":META_REV if name in categories else AETHER_REV,
    "sha256":digest,"entries":entries,"unsupported_entries":unsupported,"status":"loaded","url":jobs[name]})
 if failures or set(loaded)!=set(jobs):
  raise RuntimeError("required source snapshot failed: "+", ".join(sorted(set(failures)|(set(jobs)-set(loaded)))))
 selected=[];seen=set()
 for source,quota in SEED_QUOTAS.items():
  rule=loaded.get(source,{"exact":set(),"suffix":set()});candidates=sorted(rule["exact"]|rule["suffix"]);count=0
  for domain in candidates:
   if domain in seen:continue
   tags={name for name,item in loaded.items() if matches(item,domain)}
   expected,family,review=expectation(tags,domain)
   if expected=="UNKNOWN":continue
   selected.append({"domain":domain,"expected":expected,"family":family,"seed_source":source,
    "memberships":sorted(tags),"policy_review":review});seen.add(domain);count+=1
   if count>=quota:break
 for domain,(route,family) in POLICY_ANCHORS.items():
  tags={name for name,item in loaded.items() if matches(item,domain)}
  selected=[row for row in selected if row["domain"]!=domain]
  selected.append({"domain":domain,"expected":route,"family":family,"seed_source":"user-policy",
   "memberships":sorted(tags),"policy_review":False});seen.add(domain)
 if len(selected)<2000:raise RuntimeError(f"corpus too small: {len(selected)}")
 selected.sort(key=lambda row:row["domain"]);write_corpus(selected,OUT)
 manifest["sources"].sort(key=lambda row:row["name"]);manifest["sample_count"]=len(selected)
 manifest["corpus_sha256"]=hashlib.sha256(OUT.read_bytes()).hexdigest()
 PACK.parent.mkdir(parents=True,exist_ok=True)
 packed=json.dumps(raw_sources,ensure_ascii=False,sort_keys=True,separators=(",",":")).encode()
 buffer=io.BytesIO()
 with gzip.GzipFile(filename="",mode="wb",fileobj=buffer,mtime=0) as stream:stream.write(packed)
 PACK.write_bytes(buffer.getvalue());manifest["snapshot_pack_sha256"]=hashlib.sha256(PACK.read_bytes()).hexdigest()
 MANIFEST.write_text(json.dumps(manifest,ensure_ascii=False,indent=2,sort_keys=True)+"\n",encoding="utf-8",newline="\n")
 print(json.dumps({"samples":len(selected),"corpus_sha256":manifest["corpus_sha256"]}))

if __name__=="__main__":main()
