#!/usr/bin/env python3
import contextlib,hashlib,io,json,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
import build_routing_samples as builder
import simulate_routing as simulator
import routing_sources

class RoutingSimulatorTests(unittest.TestCase):
 def test_corpus_writer_uses_stable_utf8_lf_bytes(self):
  rows=[{"domain":"example.com","expected":"策略"},{"domain":"sub.example.com","expected":"DIRECT"}]
  with tempfile.TemporaryDirectory() as directory:
   target=Path(directory)/"nested"/"samples.jsonl"
   builder.write_corpus(rows,target)
   expected="".join(json.dumps(row,ensure_ascii=False,sort_keys=True)+"\n" for row in rows).encode("utf-8")
   self.assertEqual(target.read_bytes(),expected)
   self.assertNotIn(b"\r",target.read_bytes())

 def test_corpus_is_large_unique_and_reproducible(self):
  self.assertEqual({p.name for p in (ROOT/"tests/routing-sources").iterdir()},{"NOTICE.md"})
  rows=[json.loads(line) for line in simulator.CORPUS.read_text(encoding="utf-8").splitlines() if line]
  self.assertGreaterEqual(len(rows),2000);self.assertEqual(len(rows),len({row["domain"] for row in rows}))
  manifest=json.loads(simulator.MANIFEST.read_text(encoding="utf-8"));loaded=simulator.verified_sources(manifest)
  self.assertNotIn("snapshot_pack_sha256",manifest)
  self.assertTrue(all("text" not in source for source in manifest["sources"]))
  self.assertEqual({row["name"] for row in manifest["sources"]},set(loaded))
  for row in rows:
   self.assertEqual(row["memberships"],sorted(name for name,rule in loaded.items() if builder.matches(rule,row["domain"])))

 def test_five_domain_syntaxes_and_bare_exact(self):
  text="""payload:
  - 'DOMAIN,exact.example'
  - '+.suffix.example'
  - 'DOMAIN-KEYWORD,needle'
  - 'DOMAIN-WILDCARD,time*.example'
  - 'DOMAIN-REGEX,^clock[0-9]+\\.example$'
  - 'bare.example'
"""
  rule,unsupported=builder.patterns(text);self.assertEqual(unsupported,0)
  for domain in ("exact.example","a.suffix.example","suffix.example","has-needle.example","time12.example","clock7.example","bare.example"):
   self.assertTrue(builder.matches(rule,domain),domain)
  self.assertFalse(builder.matches(rule,"sub.exact.example"));self.assertFalse(builder.matches(rule,"sub.bare.example"))

 def test_local_classical_domains_ignore_non_domain_conditions(self):
  rule=simulator.local_patterns(ROOT/"rules/connectivity-check.yaml",True)
  for domain in ("connectivitycheck.gstatic.com","x.msftconnecttest.com","my-connectivitycheck.test","time7.apple.com","time3.windows.com"):
   self.assertTrue(simulator.domain_match(domain,rule),domain)
  webrtc=simulator.local_patterns(ROOT/"rules/webrtc-client.yaml",True)
  self.assertFalse(simulator.domain_match("example.com",webrtc))

 def test_user_policy_anchors_are_present(self):
  rows={json.loads(line)["domain"]:json.loads(line) for line in simulator.CORPUS.read_text(encoding="utf-8").splitlines() if line}
  for domain in builder.POLICY_ANCHORS:self.assertEqual(rows[domain]["expected"],builder.POLICY_ANCHORS[domain][0])

 def test_full_run_covers_committed_corpus(self):
  with contextlib.redirect_stdout(io.StringIO()):summary,results=simulator.run(False)
  self.assertGreaterEqual(summary["samples"],2000);self.assertEqual(summary["samples"],len(results));self.assertEqual(summary["unknown"],0)

 def test_cached_downloads_and_corrupt_corpus_fail_closed(self):
  raw=b"payload:\n  - '+.example.com'\n"
  source={"name":"fixture","status":"loaded","revision":"a"*40,"sha256":hashlib.sha256(raw).hexdigest(),
          "url":"https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/"+"a"*40+"/fixture.yaml"}
  with tempfile.TemporaryDirectory() as directory:
   directory=Path(directory)
   with patch.object(routing_sources,"urlopen",return_value=io.BytesIO(raw)) as request:
    self.assertEqual(routing_sources.verified_source(source,directory),raw.decode());self.assertEqual(request.call_count,1)
   with patch.object(routing_sources,"urlopen",side_effect=AssertionError("cache must avoid network")):
    self.assertEqual(routing_sources.verified_source(source,directory),raw.decode())
    (directory/(source["sha256"]+".raw")).write_bytes(b"corrupt")
    with self.assertRaisesRegex(RuntimeError,"sha256 mismatch"):routing_sources.verified_source(source,directory)
   (directory/(source["sha256"]+".raw")).unlink()
   with patch.object(routing_sources,"urlopen",return_value=io.BytesIO(b"wrong upstream")):
    with self.assertRaisesRegex(RuntimeError,"sha256 mismatch"):routing_sources.verified_source(source,directory)
   self.assertFalse((directory/(source["sha256"]+".raw")).exists())
   with patch.object(routing_sources,"urlopen",side_effect=OSError("offline")):
    with self.assertRaises(OSError):routing_sources.verified_source(source,directory)
   with self.assertRaises(RuntimeError):routing_sources.source_texts({"sources":[dict(source,status="failed")]},directory)
   with self.assertRaises(RuntimeError):routing_sources.source_texts({"sources":[dict(source,url=source["url"].replace("a"*40,"main"))]},directory)
   manifest=json.loads(simulator.MANIFEST.read_text(encoding="utf-8"))
   bad_corpus=directory/"samples.jsonl";bad_corpus.write_bytes(simulator.CORPUS.read_bytes()+b"\n")
   with patch.object(simulator,"CORPUS",bad_corpus),self.assertRaises(SystemExit),contextlib.redirect_stdout(io.StringIO()):simulator.run(False)
   rows=simulator.CORPUS.read_text(encoding="utf-8").splitlines();first=json.loads(rows[0]);first["memberships"]=[];rows[0]=json.dumps(first,ensure_ascii=False,sort_keys=True)
   bad_corpus.write_text("\n".join(rows)+"\n",encoding="utf-8",newline="\n");changed=dict(manifest);changed["corpus_sha256"]=hashlib.sha256(bad_corpus.read_bytes()).hexdigest()
   bad_manifest=directory/"manifest.json";bad_manifest.write_text(json.dumps(changed),encoding="utf-8")
   with patch.object(simulator,"CORPUS",bad_corpus),patch.object(simulator,"MANIFEST",bad_manifest),self.assertRaises(SystemExit),contextlib.redirect_stdout(io.StringIO()):simulator.run(False)

 def test_first_domain_rule_wins(self):
  old=simulator.TARGET_ROOT
  with tempfile.TemporaryDirectory() as directory:
   directory=Path(directory);(directory/"rules").mkdir();(directory/"metafenliu.ini").write_text("ruleset=DIRECT,[]DOMAIN-SUFFIX,example.com\nruleset=PROXY,[]DOMAIN,api.example.com\nruleset=FINAL,[]FINAL\n",encoding="utf-8")
   simulator.TARGET_ROOT=directory;rules=simulator.ordered_rules();row={"domain":"api.example.com","memberships":[]}
   self.assertEqual(simulator.simulate(row,rules,{})["actual"],"DIRECT")
  simulator.TARGET_ROOT=old

if __name__=="__main__":unittest.main()
