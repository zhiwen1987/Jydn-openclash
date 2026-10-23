"""Auxiliary notice-enum evidence, never a replacement for product acceptance.

The original unmodified negative verifier is replayed first. Notice text is
not public: its enum is a source-bound trusted-CI rendered-DOM observation,
not an independently recomputed raw-text or browser attestation.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import re

_spec=importlib.util.spec_from_file_location('feedback_original_negative',Path(__file__).with_name('check_handoff_negative_ui.py'))
B=importlib.util.module_from_spec(_spec); _spec.loader.exec_module(B)
H=B.H
need,exact,same,integer,boolean=H.need,H.exact,H.same,H.integer,H.boolean
read,decode,canonical,sha,git_bytes=H.read,H.decode,H.canonical,H.sha,H.git_bytes
CONTRACT_PATH='chengwang/tools/subscription-ui-browser/handoff-feedback-contract.json'
CONTRACT_FILE=Path(__file__).parents[2]/'tools/subscription-ui-browser/handoff-feedback-contract.json'
CONTRACT_RAW=read(CONTRACT_FILE,65536)
CONTRACT=decode(CONTRACT_RAW)
PREFIX=b'SUBSCRIPTION_UI_FEEDBACK='
SUCCESS=b'SUBSCRIPTION_UI=CAPTURED independent_verification=pending production=false full_subscription_e2e=false\n'
SOURCE_PATHS=(
    'chengwang/deploy/subscription-ui-browser/check_handoff_feedback.py',
    CONTRACT_PATH,
    'chengwang/tools/subscription-ui-browser/handoff-feedback-contract.mjs',
    'chengwang/tools/subscription-ui-browser/handoff-feedback-observer.mjs',
    'chengwang/tools/subscription-ui-browser/handoff-negative-driver.mjs',
    'chengwang/deploy/subscription-ui-browser/run_subscription_ui.py',
    'chengwang/web/src/Subscriptions.tsx',
    'chengwang/tools/subscription-browser/collect-subscription-dom.mjs',
    'chengwang/deploy/subscription-ui-browser/feedback_projection.py',
)
COPIED_PATHS=SOURCE_PATHS[1:6]+SOURCE_PATHS[7:]


def validate_contract():
    same(CONTRACT['schema'],'chengwang.handoff-feedback-contract/v1'); same(CONTRACT['scenario'],'remote_handoff_negative')
    same(CONTRACT['prefix'],PREFIX.decode()); same(CONTRACT['steps'],B.STEPS)
    same(CONTRACT['maxRows'],49); same(CONTRACT['maxLineBytes'],1024); same(CONTRACT['maxProjectionBytes'],65536)
    same(CONTRACT['domRowHash'],'SHA256_OF_EXACT_UTF8_DOM_JSON_LINE_INCLUDING_LF')
    same(CONTRACT['observationKeys'],['schema','ordinal','step','domRowSHA256','status','alert','statusVisible','alertVisible'])
    same(CONTRACT['snapshotKeys'],['status','alert','statusVisible','alertVisible'])
    same(CONTRACT['production'],False); same(CONTRACT['authorization'],'BLOCKED'); same(CONTRACT['fullSubscriptionE2EProven'],False)
    same(CONTRACT['unknownText'],'REJECT_NOT_RAW_EXPORT')


def validate_transcript(raw, dom_raw):
    validate_contract()
    need(type(raw) is bytes and raw.endswith(SUCCESS) and len(raw)<=CONTRACT['maxProjectionBytes']+len(SUCCESS))
    need(type(dom_raw) is bytes and 0<len(dom_raw)<=B.CONTRACT['maxDOMFileBytes'] and dom_raw.endswith(b'\n'))
    projection=raw[:-len(SUCCESS)]; need(0<len(projection)<=CONTRACT['maxProjectionBytes'])
    lines=projection.splitlines(keepends=True); dom_lines=dom_raw.splitlines(keepends=True)
    same(len(lines),49); same(len(dom_lines),49); records=[]
    for ordinal,(line,dom_line,step) in enumerate(zip(lines,dom_lines,CONTRACT['steps']),1):
        need(type(line) is bytes and 0<len(line)<=CONTRACT['maxLineBytes'] and re.fullmatch(rb'[\x20-\x7e]+\n',line) and line.startswith(PREFIX))
        need(dom_line.endswith(b'\n') and not dom_line.endswith(b'\r\n'))
        value=decode(line[len(PREFIX):-1]); exact(value,CONTRACT['observationKeys'])
        same(list(value),CONTRACT['observationKeys'])
        same(json.dumps(value,ensure_ascii=True,separators=(',',':')).encode('ascii'),line[len(PREFIX):-1])
        same(value['schema'],CONTRACT['observationSchema']); same(value['ordinal'],ordinal); same(value['step'],step)
        same(value['domRowSHA256'],sha(dom_line))
        snapshot={k:value[k] for k in CONTRACT['snapshotKeys']}; same(snapshot,CONTRACT['expected'][step])
        need(type(value['status']) is str and value['status'] in CONTRACT['statusTexts'] and type(value['alert']) is str and value['alert'] in CONTRACT['alertTexts'])
        boolean(value['statusVisible']); boolean(value['alertVisible'])
        dom=decode(dom_line); same(dom['schema'],B.CONTRACT['domSchema']); same(dom['ordinal'],ordinal); same(dom['step'],step)
        inner=dom['dom']; boolean(inner['pageVisible']); boolean(inner['alertVisible'])
        same(value['alertVisible'],inner['alertVisible']); same(value['statusVisible'],value['status']!='ABSENT' and inner['pageVisible'])
        # This binds the enum to the same-task original row. It cannot turn an
        # unpublished notice string into independently verifiable raw text.
        records.append(value)
    return records


def validate_sources(repo, commit, originals, source_raw=None):
    isolation=decode(read(originals/'isolation.json') if source_raw is None else source_raw['isolation'])
    inputs=decode(read(originals/'inputs.json') if source_raw is None else source_raw['inputs'])
    sources={item['path']:item for item in isolation['sourceFilesBefore']}; copied={item['path']:item for item in inputs['copiedInputs']}
    bindings=[]
    for path in SOURCE_PATHS:
        need(path in sources); original=git_bytes(repo,commit,path)
        expected=dict(path=path,bytes=len(original),sha256=sha(original)); same(sources[path],expected); bindings.append(expected)
        if path in COPIED_PATHS: need(path in copied); same(copied[path],expected)
    same(git_bytes(repo,commit,SOURCE_PATHS[0]),read(Path(__file__)))
    same(git_bytes(repo,commit,CONTRACT_PATH),CONTRACT_RAW)
    return bindings


def verify(evidence, repo, commit, engine):
    need(type(commit) is str and re.fullmatch(r'[a-f0-9]{40}',commit) and engine in ('chrome-cdp','playwright'))
    need(not evidence.is_symlink()); originals=evidence/'originals'; need(originals.is_dir() and not originals.is_symlink())
    report_path=evidence/'independent.json'; log_path=evidence/'supervisor-original.log'; dom_path=originals/'dom.jsonl'
    files=[('business',report_path,16<<20),('transcript',log_path,CONTRACT['maxProjectionBytes']+len(SUCCESS)),('dom',dom_path,1<<20),('isolation',originals/'isolation.json',16<<20),('inputs',originals/'inputs.json',16<<20)]
    before={name:read(path,limit) for name,path,limit in files}
    business=B.verify(originals,repo,commit,engine)
    same(before['business'],canonical(business)+b'\n')
    need(business['outcome']=='PASS' and business['sourceCommit']==commit and business['engine']==engine and business['production'] is False and business['authorization']=='BLOCKED' and business['fullSubscriptionE2EProven'] is False)
    for name,path in (('dom','dom.jsonl'),('isolation','isolation.json'),('inputs','inputs.json')): same(sha(before[name]),business['evidenceSHA256'][path])
    records=validate_transcript(before['transcript'],before['dom']); bindings=validate_sources(repo,commit,originals,before)
    same({name:read(path,limit) for name,path,limit in files},before)
    return dict(schema='chengwang.handoff-feedback-verification/v1',sourceCommit=commit,engine=engine,fixtureId=business['fixtureId'],scenario='remote_handoff_negative',outcome='PASS',scope=CONTRACT['scope'],observations=49,
        knownHandoff409FeedbackStages=4,crossOwner403FeedbackStages=1,ownFailedReceiptFeedbackStages=5,normalBusinessEvidenceIndependentlyReplayed=True,originalBusinessVerifierModified=False,sourceGitBlobs=business['sourceGitBlobs'],sourceBindings=bindings,
        businessReportSHA256=sha(before['business']),publicSupervisorTranscriptSHA256=sha(before['transcript']),exactDOMJSONLSHA256=sha(before['dom']),feedbackContractSHA256=sha(CONTRACT_RAW),feedbackRowsSHA256=sha(before['transcript'][:-len(SUCCESS)]),
        observationTrust='SOURCE_BOUND_TRUSTED_CI_SAME_TASK_RENDERED_DOM_ENUM_NOT_INDEPENDENT_BROWSER_ATTESTATION',rawNoticeTextIndependentlyVerified=False,packetEvidenceProven=False,perHTTPFeedbackCausalityProven=False,
        unknownResultRealBrowserProven=False,timeoutRealBrowserProven=False,completeUXClosureProven=False,screenshotVisualReviewProven=False,fullSubscriptionE2EProven=False,production=False,authorization='BLOCKED',
        remaining=['Real unknown result and timeout feedback without mock','Keyboard screen-reader and offscreen UX acceptance','Remaining B01-B23 and production rollback acceptance'])


def main():
    parser=argparse.ArgumentParser()
    for name in ('evidence','repo','report'): parser.add_argument('--'+name,required=True,type=Path)
    parser.add_argument('--source-commit',required=True); parser.add_argument('--engine',required=True,choices=('chrome-cdp','playwright')); args=parser.parse_args()
    evidence=args.evidence.resolve(strict=True); repo=args.repo.resolve(strict=True); report=args.report.absolute()
    need(not args.evidence.is_symlink() and not args.repo.is_symlink() and not report.exists() and not report.is_symlink() and not report.resolve().is_relative_to(evidence) and not report.resolve().is_relative_to(repo))
    value=verify(evidence,repo,args.source_commit,args.engine)
    with report.open('xb') as output: output.write(canonical(value)+b'\n')
    print('HANDOFF_FEEDBACK=VERIFIED trusted_ci_dom_enum=true raw_notice_independently_verified=false production=false')


if __name__=='__main__':
    try: main()
    except Exception: raise SystemExit('HANDOFF_FEEDBACK=REJECTED raw_input_suppressed=true') from None
