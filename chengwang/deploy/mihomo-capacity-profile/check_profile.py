"""Independent fixed-profile bytes/source/event reader; never executes Go."""
import argparse
import base64
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import types
import zlib

TOP='TestLifecycleRecoveryCapacityAndRevisionReserveFailBeforeStop'
PACKAGE='chengwang/internal/mihomodeploy'
PRIVATE='/tmp/chengwang-capacity-profile-private'
TAG='chengwang_capacity_profile'
GO_ARGS=['test','-race','-json','-count=1','-timeout=180s','-tags',TAG,'-run','^'+TOP+'$','./internal/mihomodeploy']
FULL_PACKAGES=['./internal/adapter/mihomo','./internal/mihomodeploy','./internal/authn','./internal/api','./internal/serverruntime','./internal/authz']
FULL_GO_ARGS=['test','-race','-json','-count=1','-timeout=180s','-tags',TAG,'-run','^Test',*FULL_PACKAGES]
CAPACITY_FMT=['internal/mihomodeploy/lifecycle_capacity_profile_linux_test.go']
FULL_FMT=[*CAPACITY_FMT,
    'internal/mihomodeploy/lifecycle_recovery_checkpoint.go',
    'internal/mihomodeploy/lifecycle_recovery_completion.go',
    'internal/mihomodeploy/lifecycle_recovery_completion_test.go',
    'internal/mihomodeploy/lifecycle_completion_shape_diagnostic_test.go',
    'internal/mihomodeploy/lifecycle_v3_decode_scope_test.go',
    'internal/mihomodeploy/lifecycle_current_epoch.go',
    'internal/mihomodeploy/lifecycle_current_epoch_test.go',
    'internal/mihomodeploy/lab_current_epoch_runtime.go',
    'internal/mihomodeploy/lab_current_epoch_runtime_test.go',
    'internal/adapter/mihomo/lab_reload_response_schedule_linux.go',
    'internal/adapter/mihomo/lab_reload_response_schedule_linux_test.go',
    'internal/mihomodeploy/lab_service.go',
    'internal/mihomodeploy/lab_continuous_recovery_fault_default.go',
    'internal/mihomodeploy/lab_continuous_recovery_fault_linux.go',
    'internal/mihomodeploy/lab_continuous_recovery_fault_linux_test.go',
    'internal/serverruntime/runtime.go',
    'internal/serverruntime/mihomo_continuous_recovery_e2e_linux_test.go',
    'internal/serverruntime/mihomo_continuous_recovery_hook_default.go',
    'internal/serverruntime/mihomo_continuous_recovery_hook_linux.go']
FULL_REQUIRED_PIN='b0a464294a9dcaf7bea46ea29c0e7bc4937acc63b16df05387d3652efbbcb280'
FULL_PREVIOUS_661_PIN='3a8336389d2196c1dbe6f250b8a7cdeeff83af9a83d97bc4294ec8695b3e17fa'
FULL_CORE_D_ADDED=frozenset({
    'chengwang/internal/api::TestMihomoRecoveryAPIInspectExposesOnlyBoundedFailureExitMODEL',
    'chengwang/internal/api::TestMihomoRecoveryAPIInspectExposesReconciledFreshCreateExitMODEL',
    'chengwang/internal/api::TestMihomoRecoveryAPIInspectRemainsReadOnlyAndFailureStatusIsStrictMODEL',
    'chengwang/internal/api::TestMihomoRecoveryAPIMutatingSuccessAndReplayAlwaysReportChangedMODEL',
    'chengwang/internal/mihomodeploy::TestLabRecoveryCaptureNamespaceIsDistinctAndSourceDerivedMODEL',
    'chengwang/internal/mihomodeploy::TestLabRecoveryCleanupCustodyCannotSerializeOrSurviveMutationMODEL',
    'chengwang/internal/mihomodeploy::TestLabRecoveryCleanupIssuerDiscardIsExactAtomicAndReleasesGraphMODEL',
    'chengwang/internal/mihomodeploy::TestLabRecoveryOwnerExpiryReplacementRejectsOldTokenAndPreservesHistoryMODEL',
    'chengwang/internal/mihomodeploy::TestLabRecoveryPhysicalFailureStagesExposeBoundedInspectExitMODEL',
    'chengwang/internal/mihomodeploy::TestLabRecoveryReconcileRequiresFreshExactInitiatorPrepareMODEL',
    'chengwang/internal/mihomodeploy::TestLabRecoveryReconcileAuthenticatesBeforeBusyOrExecutingConflictMODEL',
    'chengwang/internal/mihomodeploy::TestLabRecoveryReconciliationRetryRetainsCustodyOnceAndThenLocksMODEL',
    'chengwang/internal/mihomodeploy::TestLabRecoveryRecordContextCoversRecordAndCancelsAfterReturnMODEL',
    'chengwang/internal/mihomodeploy::TestLabRecoveryRevokedFirstPlanBeginsFreshV1WithoutFacadeMODEL',
    'chengwang/internal/mihomodeploy::TestLabRecoveryStaleAuthorizedCheckCannotSpendAttemptMODEL',
    'chengwang/internal/mihomodeploy::TestLabRecoveryTerminalPrePermitFailureAndCloseDiscardUnclaimedCustodyMODEL',
    'chengwang/internal/mihomodeploy::TestLabRecoveryUnstartedCleanupConsumesActualLinuxStartFailureOnce',
    'chengwang/internal/mihomodeploy::TestLabRecoveryUnstartedCleanupCustodyIsAtomicOneUseForNormalAndAbsentMODEL',
    'chengwang/internal/mihomodeploy::TestLabRecoveryUnstartedCleanupRejectsProcessUnknownAndUnjoinedMODEL',
    'chengwang/internal/mihomodeploy::TestLabRecoveryWithoutFacadeNeverDowngradesOrBypassesV2CurrentOwnerMODEL',
    'chengwang/internal/mihomodeploy::TestLifecycleRecoveryAbsentCleanupRequiresPersistedSourceIdentity',
    'chengwang/internal/mihomodeploy::TestLifecycleRecoveryAbsentExecutionSchemaPairsAreClosed',
    'chengwang/internal/mihomodeploy::TestLifecycleRecoveryCleanupAttemptRejectsSparseOrForeignShapes',
    'chengwang/internal/mihomodeploy::TestLifecycleRecoveryReconcileCompatibilityAndAuthorityNegatives',
    'chengwang/internal/mihomodeploy::TestLifecycleRecoveryReconcileReserveAccountsForCompleteAttemptAtControlLimit',
    'chengwang/internal/mihomodeploy::TestLifecycleRecoveryReconcileReserveRejectsFullHistoryBeforeAction',
    'chengwang/internal/mihomodeploy::TestLifecycleRecoveryReconciledStrictlyRestoresOriginalUnknown',
})
FULL_OLD_660_PIN='3093151172b8c18d088a7d217bcf0d9d16a1a85b710d121f9d7c12427fe46b16'
FULL_PREVIOUS_647_PIN='1e7db484a7eb5485b06037bd3ee1fb443201ab46799c17fefba9bcba9b0cca94'
FULL_PREVIOUS_635_PIN='1be6eaf9abe7f03253410f6db950935f33162a30deee033c6cd401666ade36d6'
FULL_RECOVERY_COMPLETION_CURRENT_ADDED=frozenset({
    'chengwang/internal/mihomodeploy::TestLabCurrentEpochRuntimeRejectsPoisonedOrForeignDiskWithoutLegacyFallback',
    'chengwang/internal/mihomodeploy::TestLabCurrentEpochRuntimeRejectsUnissuedHandoffAndPreservesCloseOwner',
    'chengwang/internal/mihomodeploy::TestLabCurrentEpochRuntimeSnapshotIsDetachedReadOnly',
    'chengwang/internal/mihomodeploy::TestLifecycleCloneSchemaDigestForRecoveryCompletion',
    'chengwang/internal/mihomodeploy::TestLifecycleRecoveryCompletionActualCloneShapeDiagnostic',
    'chengwang/internal/mihomodeploy::TestLifecycleCurrentEpochGenericCandidateCannotIssuePublication',
    'chengwang/internal/mihomodeploy::TestLifecycleCurrentEpochLedgerRejectsResealedCorruptProjection',
    'chengwang/internal/mihomodeploy::TestLifecycleCurrentEpochMutationRejectsOwnerAndRevisionBypass',
    'chengwang/internal/mihomodeploy::TestLifecycleCurrentEpochProjectionDetachesNestedMutableState',
    'chengwang/internal/mihomodeploy::TestLifecycleCurrentEpochProjectionDoesNotRelaxLegacyGenesis',
    'chengwang/internal/mihomodeploy::TestLifecycleRecoveryCompletionCapabilitiesArePrivateAndOneStoreBound',
    'chengwang/internal/mihomodeploy::TestLifecycleRecoveryCompletionCheckpointReconstructsExactVerifiedRoot',
})
FULL_LOCK_ORDER_ADDED=frozenset({
    'chengwang/internal/mihomodeploy::TestLabRecoveryCollectorCurrentKernelLockBoundaryMODEL',
})
FULL_RECOVERY_COMPLETION_CURRENT_FINAL_ADDED=frozenset({
    'chengwang/internal/mihomodeploy::TestLifecycleRecoveryCompletionProspectiveMetadataUsesStrictS2Preimage',
    'chengwang/internal/mihomodeploy::TestLifecycleRecoveryCompletionCustodyRejectsCopiesForeignResetAndReopen',
    'chengwang/internal/mihomodeploy::TestLifecycleCurrentEpochNilHandoffRejectsBeforeRecoveryMutation',
    'chengwang/internal/mihomodeploy::TestLifecycleCurrentEpochCopiedReceiverCannotUseOrRetireBackend',
    'chengwang/internal/mihomodeploy::TestLifecycleCurrentEpochRollbackPoisonsBothStoresPermanently',
    'chengwang/internal/mihomodeploy::TestLifecycleV3GlobalBudgetCountsEveryEpochAndUniqueRecovery',
    'chengwang/internal/mihomodeploy::TestLifecycleCurrentEpochObservationCapacityCountsRetiredEpochs',
    'chengwang/internal/mihomodeploy::TestLifecycleCurrentEpochHandoffRequiresCompletedHistoryTail',
    'chengwang/internal/mihomodeploy::TestLifecycleCurrentEpochReverseProjectionDetachesNestedState',
    'chengwang/internal/mihomodeploy::TestLifecycleV3DecodeScopeMemoUsesExactCanonicalBytesAndDetachedValues',
    'chengwang/internal/mihomodeploy::TestLifecycleV3DecodeScopeCheckpointRootIsStrictlyValidatedOnce',
    'chengwang/internal/mihomodeploy::TestLifecycleV3DecodeScopesNeverShareValidationAcrossOperations',
    'chengwang/internal/mihomodeploy::TestLifecycleV3DecodeScopeDeepChainBudgetsFailClosed',
}) | FULL_LOCK_ORDER_ADDED
FULL_PREVIOUS_627_PIN='3bd65c00bb45bbef41763cadf7b8b98c6c0ce2fbc8ec93b3bb8dfa6dd0880543'
FULL_DURABLE_S2_ADDED=frozenset({
    'chengwang/internal/mihomodeploy::TestLifecycleRecoveryVerificationTypedFactRejectsUnissuedRecordCapability',
    'chengwang/internal/mihomodeploy::TestLifecycleRecoveryVerificationVersionedCodecPreservesLegacyExecutionBytes',
    'chengwang/internal/mihomodeploy::TestLifecycleRecoveryVerifiedBoundsCoordinatedTamperRejectsAfterReseal',
    'chengwang/internal/mihomodeploy::TestLifecycleRecoveryVerifiedBoundsGenericPublisherCannotMintOrReplaceFact',
    'chengwang/internal/mihomodeploy::TestLifecycleRecoveryVerifiedBoundsNestedValuesAreDetached',
    'chengwang/internal/mihomodeploy::TestLifecycleRecoveryVerifiedBoundsObservationRequiresExactBoundSlicesAndDigests',
    'chengwang/internal/mihomodeploy::TestLifecycleRecoveryVerifiedBoundsUnissuedCopiedAndForeignCapsCannotPublish',
    'chengwang/internal/mihomodeploy::TestLifecycleRecoveryVerifiedBoundsWindowIdentityAndSourceStayBound',
})
FULL_PREVIOUS_619_PIN='8a2587e2dfbf54c6a56a3de75b8c728429e69c40d74bc654cb773a9cf96516ac'
FULL_LOCAL_MARKER_ADDED=frozenset({
    'chengwang/internal/mihomodeploy::TestLabRecoveryMarkerBoundsCounterRolesAreExactAndOrdered',
    'chengwang/internal/mihomodeploy::TestLabRecoveryMarkerBoundsMatchedRequiresThreeCompleteBoundBodies',
    'chengwang/internal/mihomodeploy::TestLabRecoveryMarkerBoundsNonceAndMarkerDTOCannotIssueReceipt',
    'chengwang/internal/mihomodeploy::TestLabRecoveryMarkerBoundsSelectedAndUnselectedDeltasStayExact',
    'chengwang/internal/mihomodeploy::TestLabRecoveryMarkerBoundsTimesRolesFlagsAndNonnegativeCountersFailClosed',
    'chengwang/internal/mihomodeploy::TestLabRecoveryMarkerBoundsUnissuedCopiedCrossFixtureAndClosedReceiptsReject',
    'chengwang/internal/mihomodeploy::TestLabRecoveryMarkerClosedDiagnosticNamesAndDetachedProjection',
    'chengwang/internal/mihomodeploy::TestLabRecoveryMarkerUnissuedServiceAndReceiptCannotAuthorize',
})
FULL_PREVIOUS_611_PIN='327f5833d99a02a12170b894aec43da81432c85c6de78338b15532ab3572e79c'
FULL_S2_COLLECTOR_ADDED=frozenset({
    'chengwang/internal/adapter/mihomo::TestLabSampleTimesDoesNotGrantStabilityOrFreshness',
    'chengwang/internal/adapter/mihomo::TestLabSampleTimesRejectsCorruptSamplesAndTimeOrders',
    'chengwang/internal/adapter/mihomo::TestLabSampleTimesUsesOpaqueCaptureAndReturnsDetachedValues',
    'chengwang/internal/mihomodeploy::TestLabRecoveryCollectorAbsoluteWindowRejectsFutureStaleAndReordering',
    'chengwang/internal/mihomodeploy::TestLabRecoveryCollectorCaptureNamesStayClosed',
    'chengwang/internal/mihomodeploy::TestLabRecoveryCollectorEntryAndSerializedEvidenceReject',
    'chengwang/internal/mihomodeploy::TestLabRecoveryCollectorModelS1CannotMintNativeCustody',
    'chengwang/internal/mihomodeploy::TestLabRecoveryCollectorSourceDeadlineUsesAllSixBounds',
})
FULL_PREVIOUS_607_PIN='b745efef5b96ad29ececc9f9e4bf465d23277de5c03ff805c8c675abb100da62'
FULL_SELECTED_TARGET_ADDED=frozenset({
    'chengwang/internal/adapter/mihomo::TestLabTargetReadbackClosedMappingAndReportOwnership',
    'chengwang/internal/adapter/mihomo::TestLabTargetReadbackMatchesEitherSelectedEpochWithoutOldNewClaim',
    'chengwang/internal/adapter/mihomo::TestLabTargetReadbackPreservesProjectionAndWitnessInstability',
    'chengwang/internal/adapter/mihomo::TestLabTargetReadbackRetainsOriginalInputDigestAndTimeGuards',
})
FULL_PREVIOUS_591_PIN='bd98cdb360c8eb7fd8c90f0a7a2855a9d8135a3a832f77cfd115ac39c5078857'
FULL_S1_STARTED_ADDED=frozenset({
    'chengwang/internal/mihomodeploy::TestLifecycleRecoveryStartedExecutionCannotUseGenericPublisherOrBeRemoved',
    'chengwang/internal/mihomodeploy::TestLifecycleRecoveryStartedExecutionCodecRejectsAlteredFactsAndPreimage',
    'chengwang/internal/mihomodeploy::TestLifecycleRecoveryStartedExecutionGenericEarlyReturnsCannotMintDTO',
    'chengwang/internal/mihomodeploy::TestLifecycleRecoveryStartedExecutionNilMatchesOrderedOldTxnBytes',
    'chengwang/internal/mihomodeploy::TestLifecycleRecoveryStartedRecordConcurrentCopiesWriteExactlyOnce',
    'chengwang/internal/mihomodeploy::TestLifecycleRecoveryStartedRecordEveryAdmittedContextFailureSpendsCapability',
    'chengwang/internal/mihomodeploy::TestLifecycleRecoveryStartedRecordExpiryPreservesFactWithoutNewPermission',
    'chengwang/internal/mihomodeploy::TestLifecycleRecoveryStartedRecordFailedActualReadbackNeverAdoptsCandidate',
    'chengwang/internal/mihomodeploy::TestLifecycleRecoveryStartedRecordFailedPublicationDoesNotAdoptOrRetry',
    'chengwang/internal/mihomodeploy::TestLifecycleRecoveryStartedRecordLateRevocationKeepsOriginalFailure',
    'chengwang/internal/mihomodeploy::TestLifecycleRecoveryStartedRecordPersistsActualSourceWithoutAdvancingHead',
    'chengwang/internal/mihomodeploy::TestLifecycleRecoveryStartedRecordRejectsCopiesJSONAndCrossStoreSource',
    'chengwang/internal/mihomodeploy::TestLifecycleRecoveryStartedRecordRejectsNilAndMissingOriginWithoutRetry',
    'chengwang/internal/mihomodeploy::TestLifecycleRecoveryStartedRecordReopenClockAndOwnerCannotMintPermission',
    'chengwang/internal/mihomodeploy::TestLifecycleRecoveryStartedRecordedReopenKeepsFactButNoLiveCapability',
    'chengwang/internal/mihomodeploy::TestLifecycleRecoveryStartedReserveCoversFullBoundedRecordedFact',
})
FULL_PREVIOUS_587_PIN='14e88fa43dd23db1a77671ef4ae2b1bd36a0491b313ce7d5e3005bcc1d5d2951'
FULL_TRUSTED_CLONE_ADDED=frozenset({
    'chengwang/internal/mihomodeploy::TestLifecycleRecoveryTrustedCloneCanonicalGraphAndShape',
    'chengwang/internal/mihomodeploy::TestLifecycleRecoveryTrustedCloneKeepsRawDraftBoundary',
    'chengwang/internal/mihomodeploy::TestLifecycleRecoveryTrustedCloneRepresentationFallbackMatchesRaw',
    'chengwang/internal/mihomodeploy::TestLifecycleRecoveryTrustedCloneSplitsSiblingAliases',
})
FULL_PREVIOUS_REQUIRED_PIN='8319dfde365203ae1ae268b1a5d0a3938719bcd0671586bc66840ce2a20863c3'
FULL_CANDIDATE_SEAL_ADDED=frozenset({
    'chengwang/internal/mihomodeploy::TestLifecycleRecoveryCandidateSealPreservesExternalDigestGate',
    'chengwang/internal/mihomodeploy::TestLifecycleRecoveryCandidateSealRechecksEveryArchivedPlan'})
NORMAL_CHECKER='chengwang/deploy/mihomo-lifecycle-lab/check_contracts.py'
PUBLIC=('host-before.json','host-after.json','source-before.json','source-after.json','sandbox.json','go-version.txt',
    'gofmt.patch','gofmt.stderr','capacity.json','capacity.stderr','commands.jsonl','execution.json',
    'profile-state.json','cpu-profile.json','pprof-top.txt','pprof-top.stderr','pprof-cum.txt','pprof-cum.stderr')
RESOURCE_NAMES=('resource-before.json','resource-after.json')
RESOURCE_SCOPES={'cpuCount':'CAPTURE_PROCESS_OS_LOGICAL_CPU_COUNT','affinityCPUs':'CAPTURE_PROCESS_AFFINITY_NOT_MEASURED_GO_PID',
    'procStatCPU':'KERNEL_EXPOSED_AGGREGATE_CPU_TICKS_NOT_PROCESS','cgroupCPUMax':'CURRENT_CGROUP_FAIR_BANDWIDTH_NOT_EFFECTIVE_ANCESTOR_LIMIT',
    'cgroupCPUStat':'CURRENT_CGROUP_USAGE_AND_OWN_BANDWIDTH_COUNTERS_NOT_PER_TEST'}
CPU_STAT_FIELDS=('usage_usec','user_usec','system_usec','nr_periods','nr_throttled','throttled_usec')
ENV=sorted(['PATH','GOROOT','HOME','TMPDIR','GOCACHE','GOMODCACHE','GOPROXY','GOSUMDB','GOENV','GOTOOLCHAIN',
    'GOFLAGS','CGO_ENABLED','LANG','LC_ALL','TZ','CHENGWANG_CAPACITY_PROFILE_SOURCE_COMMIT'])
ORIGINAL_SOURCE_PINS={
    'chengwang/internal/mihomodeploy/lifecycle_recovery_transitions_test.go':'ea0a3ec623691b161680727378e1feb638157322df230b60d0f7e09534a2b7d6',
    'chengwang/internal/mihomodeploy/lifecycle.go':'026bd6b1e38bc05024aa8c26bf3195784a4e8dd0df75d7d0fcca34c941c0eb1c',
    'chengwang/internal/mihomodeploy/lab_bootstrap_state.go':'472592e381a67f1850b1518d2b47698111dada600459cf8bec2f795f4719aad5',
}

def need(v):
    if not v:raise ValueError('capacity profile evidence rejected')
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(v):return (json.dumps(v,sort_keys=True,separators=(',',':'))+'\n').encode()
def decode(raw):
    def pairs(items):
        result={}
        for k,v in items:need(k not in result);result[k]=v
        return result
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False))
def exact(value,keys):return type(value) is dict and set(value)==set(keys)
def integer(n,low=0,high=(1<<63)-1):return type(n) is int and low<=n<=high
def read(path,limit):
    need(path.is_absolute() and '..' not in path.parts)
    for part in (*reversed(path.parents),path):need(not part.is_symlink())
    before=path.lstat();need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size<=limit)
    with path.open('rb') as f:opened=os.fstat(f.fileno());raw=f.read(limit+1);after=os.fstat(f.fileno())
    identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_mode,s.st_nlink)
    need(identity(before)==identity(opened)==identity(after)==identity(path.lstat()) and len(raw)==before.st_size)
    return raw
def write(path,raw):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
    with os.fdopen(fd,'wb') as f:need(f.write(raw)==len(raw));f.flush();os.fsync(f.fileno())

def source_snapshot(repo,commit):
    need(re.fullmatch('[a-f0-9]{40}',commit) is not None)
    need(os.path.samefile(Path(__file__),repo/'chengwang/deploy/mihomo-capacity-profile/check_profile.py'))
    need(subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD']).strip().decode()==commit)
    need(subprocess.check_output(['git','-C',str(repo),'status','--porcelain','--untracked-files=all'])==b'')
    index=subprocess.check_output(['git','-C',str(repo),'ls-tree','-r','-z','--full-tree',commit])
    rows=[];total=0
    for entry in index.split(b'\0'):
        if not entry:continue
        meta,path=entry.split(b'\t',1);mode,kind,oid=meta.split(b' ');name=path.decode('utf8')
        need(mode in (b'100644',b'100755') and kind==b'blob' and not name.startswith('/') and '..' not in Path(name).parts)
        raw=read(repo/name,16<<20);total+=len(raw);need(total<=128<<20)
        need(hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==oid.decode())
        rows.append({'path':name,'bytes':len(raw),'sha256':sha(raw),'gitBlobSHA1':oid.decode()})
    need(1<=len(rows)<=4096 and len({r['path'] for r in rows})==len(rows))
    pinned={r['path']:r['sha256'] for r in rows}
    need(all(pinned.get(p)==value for p,value in ORIGINAL_SOURCE_PINS.items()))
    return {'schema':'chengwang.capacity-profile-source/v1','sourceCommit':commit,'sourceGitVerified':True,
        'originalCaseSourcePins':ORIGINAL_SOURCE_PINS,'files':rows}

def host():
    return {**{k:os.readlink('/proc/self/ns/'+v) for k,v in [('networkNamespace','net'),('mountNamespace','mnt'),('pidNamespace','pid')]},
        'resolvSHA256':sha(Path('/etc/resolv.conf').read_bytes())}

def protobuf_fields(raw):
    # Bounded protobuf wire reader, not a producer import or a protobuf dependency.
    pos=0;count=0
    def varint():
        nonlocal pos
        n=0
        for shift in range(0,70,7):
            need(pos<len(raw));v=raw[pos];pos+=1;n|=(v&127)<<shift
            if not v&128:need(n<(1<<64));return n
        need(False)
    while pos<len(raw):
        count+=1;need(count<=1000000)
        key=varint();number,wire=key>>3,key&7;need(number>0)
        if wire==0:value=varint()
        elif wire==2:
            size=varint();need(size<=len(raw)-pos);value=raw[pos:pos+size];pos+=size
        elif wire in (1,5):
            size=8 if wire==1 else 4;need(size<=len(raw)-pos);value=raw[pos:pos+size];pos+=size
        else:need(False)
        yield number,wire,value

def profile_shape(raw,diagnostic_mode='SINGLE_CASE'):
    need(0<len(raw)<=8<<20)
    decoder=zlib.decompressobj(31);proto=decoder.decompress(raw,(64<<20)+1)
    need(len(proto)<=64<<20 and decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail)
    strings=[];samples=0;function_names=[];duration=None
    for field,wire,value in protobuf_fields(proto):
        if field==6:need(wire==2);strings.append(value.decode('utf8','strict'))
        elif field==2:
            need(wire==2);samples+=1
            for tag,kind,item in protobuf_fields(value):need(tag!=3) # no profile labels
        elif field==5:
            need(wire==2);names=[item for tag,kind,item in protobuf_fields(value) if tag==2 and kind==0]
            need(len(names)==1);function_names.append(names[0])
        elif field==10:need(wire==0 and duration is None);duration=value
    need(samples>0 and function_names and integer(duration,1,180000000000))
    need(all(integer(i,0,len(strings)-1) for i in function_names))
    names=[strings[i] for i in function_names]
    if diagnostic_mode=='SINGLE_CASE':need(PACKAGE+'.'+TOP in names)
    else:need(any(name.startswith(PACKAGE+'.')for name in names))
    result={'sampleRecords':samples,'functions':len(function_names),'durationNanoseconds':duration,'profileLabelsPresent':False}
    if diagnostic_mode=='FULL_CONTRACTS':result.update({'capacityFunctionInProfile':PACKAGE+'.'+TOP in names,'sampledProcessPackage':PACKAGE})
    return result

def load_normal_checker(sources=None):
    # Execute only this fixed repository-owned checker, never Python supplied
    # in an uploaded evidence/source dictionary. CLI binds it to actual Git.
    path=Path(__file__).resolve().parents[1]/'mihomo-lifecycle-lab/check_contracts.py'
    code=read(path,1<<20)
    if sources is not None:need(type(sources)is dict and sources.get(NORMAL_CHECKER)==code)
    module=types.ModuleType('_actual_bound_normal_contract_checker');module.__file__=str(path)
    exec(compile(code,str(path),'exec'),module.__dict__)
    need(module.PACKAGES=={'chengwang'+p[1:]for p in FULL_PACKAGES} and len(module.FILES)==len(set(module.FILES))==158 and len(module.TEST_FILES)==58)
    return module

def full_source_contract(sources,manifest):
    checker=load_normal_checker(sources);need(set(sources)==set(checker.FILES))
    need(type(manifest)is dict and type(manifest.get('files'))is list)
    files={row['path']:row for row in manifest['files']};need(len(files)==len(manifest['files']))
    need(all(path in files and files[path]['sha256']==sha(raw) and files[path]['bytes']==len(raw)for path,raw in sources.items()))
    required=checker.required_names(sources)
    names=sorted(package+'::'+name for package,items in required.items()for name in items)
    need(set(required)==checker.PACKAGES and len(names)==688 and sha('\n'.join(names).encode())==FULL_REQUIRED_PIN)
    need(len(FULL_CORE_D_ADDED)==27 and FULL_CORE_D_ADDED.issubset(names))
    previous661=sorted(set(names)-FULL_CORE_D_ADDED)
    need(len(previous661)==661 and sha('\n'.join(previous661).encode())==FULL_PREVIOUS_661_PIN)
    need(len(FULL_LOCK_ORDER_ADDED)==1 and FULL_LOCK_ORDER_ADDED.issubset(previous661))
    previous660=sorted(set(previous661)-FULL_LOCK_ORDER_ADDED)
    need(len(previous660)==660 and sha('\n'.join(previous660).encode())==FULL_OLD_660_PIN)
    need(len(FULL_RECOVERY_COMPLETION_CURRENT_FINAL_ADDED)==14 and FULL_RECOVERY_COMPLETION_CURRENT_FINAL_ADDED.issubset(names))
    previous647=sorted(set(previous661)-FULL_RECOVERY_COMPLETION_CURRENT_FINAL_ADDED)
    need(len(previous647)==647 and sha('\n'.join(previous647).encode())==FULL_PREVIOUS_647_PIN)
    need(FULL_RECOVERY_COMPLETION_CURRENT_ADDED.issubset(names))
    need(not FULL_RECOVERY_COMPLETION_CURRENT_FINAL_ADDED.intersection(FULL_RECOVERY_COMPLETION_CURRENT_ADDED))
    previous635=sorted(set(previous647)-FULL_RECOVERY_COMPLETION_CURRENT_ADDED)
    need(len(previous635)==635 and sha('\n'.join(previous635).encode())==FULL_PREVIOUS_635_PIN)
    need(FULL_TRUSTED_CLONE_ADDED.issubset(names) and not FULL_TRUSTED_CLONE_ADDED.intersection(FULL_CANDIDATE_SEAL_ADDED))
    need(FULL_S1_STARTED_ADDED.issubset(names) and not FULL_S1_STARTED_ADDED.intersection(FULL_TRUSTED_CLONE_ADDED | FULL_CANDIDATE_SEAL_ADDED))
    need(FULL_SELECTED_TARGET_ADDED.issubset(names) and not FULL_SELECTED_TARGET_ADDED.intersection(FULL_S1_STARTED_ADDED | FULL_TRUSTED_CLONE_ADDED | FULL_CANDIDATE_SEAL_ADDED))
    need(FULL_S2_COLLECTOR_ADDED.issubset(names) and not FULL_S2_COLLECTOR_ADDED.intersection(FULL_SELECTED_TARGET_ADDED | FULL_S1_STARTED_ADDED | FULL_TRUSTED_CLONE_ADDED | FULL_CANDIDATE_SEAL_ADDED))
    need(FULL_LOCAL_MARKER_ADDED.issubset(names) and not FULL_LOCAL_MARKER_ADDED.intersection(FULL_S2_COLLECTOR_ADDED | FULL_SELECTED_TARGET_ADDED | FULL_S1_STARTED_ADDED | FULL_TRUSTED_CLONE_ADDED | FULL_CANDIDATE_SEAL_ADDED))
    need(FULL_DURABLE_S2_ADDED.issubset(names) and not FULL_DURABLE_S2_ADDED.intersection(FULL_LOCAL_MARKER_ADDED | FULL_S2_COLLECTOR_ADDED | FULL_SELECTED_TARGET_ADDED | FULL_S1_STARTED_ADDED | FULL_TRUSTED_CLONE_ADDED | FULL_CANDIDATE_SEAL_ADDED))
    previous627=sorted(set(previous635)-FULL_DURABLE_S2_ADDED)
    need(len(previous627)==627 and sha('\n'.join(previous627).encode())==FULL_PREVIOUS_627_PIN)
    previous619=sorted(set(previous627)-FULL_LOCAL_MARKER_ADDED)
    need(len(previous619)==619 and sha('\n'.join(previous619).encode())==FULL_PREVIOUS_619_PIN)
    previous611=sorted(set(previous619)-FULL_S2_COLLECTOR_ADDED)
    need(len(previous611)==611 and sha('\n'.join(previous611).encode())==FULL_PREVIOUS_611_PIN)
    previous607=sorted(set(previous611)-FULL_SELECTED_TARGET_ADDED)
    need(len(previous607)==607 and sha('\n'.join(previous607).encode())==FULL_PREVIOUS_607_PIN)
    previous591=sorted(set(previous607)-FULL_S1_STARTED_ADDED)
    need(len(previous591)==591 and sha('\n'.join(previous591).encode())==FULL_PREVIOUS_591_PIN)
    previous587=sorted(set(previous591)-FULL_TRUSTED_CLONE_ADDED)
    need(len(previous587)==587 and sha('\n'.join(previous587).encode())==FULL_PREVIOUS_587_PIN)
    need(FULL_CANDIDATE_SEAL_ADDED.issubset(previous587))
    previous=sorted(set(previous587)-FULL_CANDIDATE_SEAL_ADDED)
    need(len(previous)==585 and sha('\n'.join(previous).encode())==FULL_PREVIOUS_REQUIRED_PIN)
    # -run '^Test' is equivalent to the current normal test selection only
    # because none of the six packages declares Example/Fuzz entry points.
    # Audit ALL package test files bound by the complete Git manifest, not
    # only the 58 mandatory files. A future new entry point fails closed and
    # needs an explicit diagnostic-contract upgrade instead of silent omission.
    package_dirs={'chengwang'+p[1:]for p in FULL_PACKAGES};suite_test_sources={}
    repo=Path(__file__).resolve().parents[3]
    for path,row in files.items():
        if path.rsplit('/',1)[0]not in package_dirs or not path.endswith('_test.go'):continue
        need(not Path(path).is_absolute()and '..'not in Path(path).parts)
        data=read(repo/path,1<<20);need(row['sha256']==sha(data)and row['bytes']==len(data))
        text=data.decode('utf8')
        masked=re.sub(r'//[^\n]*|/\*[\s\S]*?\*/|`[^`]*`|"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'',lambda m:''.join('\n'if c=='\n'else' 'for c in m[0]),text)
        need(re.search(r'\bfunc\s+(?:Example|Fuzz)\w*\s*\(',masked)is None)
        suite_test_sources[path]=sha(data)
    completion_source='chengwang/internal/mihomodeploy/lab_native_completion_linux_test.go'
    core_d_test_sources={
        'chengwang/internal/api/mihomo_recovery_test.go',
        'chengwang/internal/mihomodeploy/lab_recovery_backend_test.go',
        'chengwang/internal/mihomodeploy/lab_recovery_unstarted_cleanup_linux_test.go',
        'chengwang/internal/mihomodeploy/lifecycle_recovery_reconcile_test.go',
    }
    continuous_test_sources={
        'chengwang/internal/adapter/mihomo/lab_reload_response_schedule_linux_test.go',
        'chengwang/internal/mihomodeploy/lab_continuous_recovery_fault_linux_test.go',
        'chengwang/internal/serverruntime/mihomo_continuous_recovery_e2e_linux_test.go',
    }
    need(completion_source in suite_test_sources and len(suite_test_sources)==91 and
         core_d_test_sources.issubset(suite_test_sources) and completion_source not in dict(checker.TEST_FILES) and
         continuous_test_sources.issubset(suite_test_sources) and
         continuous_test_sources.isdisjoint(dict(checker.TEST_FILES)) and
         all(any(p.rsplit('/',1)[0]==directory for p in suite_test_sources)for directory in package_dirs))
    previous88={path:digest for path,digest in suite_test_sources.items()if path not in continuous_test_sources}
    need(len(previous88)==88 and core_d_test_sources.issubset(previous88))
    # Preserve the previously accepted complete 84-source set explicitly.  The
    # four-tag Completion harness is source-bound but intentionally excluded
    # from ordinary mandatory names, while the four core+D sources are new.
    previous84={path:digest for path,digest in previous88.items()if path not in core_d_test_sources}
    need(len(previous84)==84 and completion_source in previous84)
    # Bind the diagnosis's six-package command to the unchanged normal race
    # command, allowing only the fixed diagnostic tag and test filter.
    normal='"${common[@]}" "$goroot/bin/go" test -race -json -count=1 -timeout=180s '+' '.join(FULL_PACKAGES)+' > "$out/race.json" 2> "$out/race.stderr"'
    need(sources['chengwang/deploy/mihomo-lifecycle-lab/run_contracts.sh'].decode().splitlines().count(normal)==1)
    return checker,required,{'sourceCount':len(sources),'mandatoryTopLevelCount':688,'mandatoryNamesSHA256':FULL_REQUIRED_PIN,
        'normalCheckerSHA256':sha(sources[NORMAL_CHECKER]),'normalRunContractsSHA256':sha(sources['chengwang/deploy/mihomo-lifecycle-lab/run_contracts.sh']),
        'completePackageTestSourceCount':len(suite_test_sources),'completePackageTestSourceSHA256':suite_test_sources,
        'previousCompletePackageTestSourceCount':len(previous88),'previousCompletePackageTestSourceSHA256':previous88,
        'historicalCompletePackageTestSourceCount':len(previous84),'historicalCompletePackageTestSourceSHA256':previous84,
        'continuousRecoveryTaggedTestSourceCount':len(continuous_test_sources),
        'continuousRecoveryTaggedTestsExcludedFromOrdinaryMandatoryNames':True,
        'completionHarnessExcludedFromOrdinaryMandatoryNames':True,
        'noExampleOrFuzzDeclarationInBoundSixPackageTestSources':True}

def full_events(raw,required,checker,go_exit,stderr=b''):
    # Diagnostic partial-reader: accept coherent failed/unfinished originals,
    # never translate them into C.events acceptance. Extra legitimate top or
    # subtests are allowed just as in the original checker; 688 is a subset.
    need(type(raw)is bytes and 0<len(raw)<=64<<20 and type(stderr)is bytes and integer(go_exit,-128,255))
    packages=checker.PACKAGES;begun=set();terminals={};states={};outputs={p:[]for p in packages}
    for line in raw.splitlines():
        need(0<len(line)<=1<<20);row=decode(line)
        need(type(row)is dict and set(row)<={'Time','Action','Package','Test','Elapsed','Output'} and row.get('Package')in packages)
        package=row['Package'];action=row.get('Action');name=row.get('Test')
        need(action in ('start','run','pause','cont','pass','fail','skip','output'))
        need(type(row.get('Time'))is str and row['Time'].endswith('Z'));datetime.datetime.fromisoformat(row['Time'].replace('Z','+00:00'))
        if 'Elapsed'in row:need(type(row['Elapsed'])in(int,float)and math.isfinite(row['Elapsed'])and row['Elapsed']>=0)
        if action=='start':need(name is None and package not in begun);begun.add(package);continue
        need(package in begun and package not in terminals)
        if name is not None:
            need(type(name)is str and 0<len(name)<=512);key=(package,name)
            if action=='run':need(key not in states and len(states)<65536);states[key]='run'
            elif action=='pause':need(states.get(key)=='run');states[key]='pause'
            elif action=='cont':need(states.get(key)=='pause');states[key]='run'
            elif action in ('pass','fail','skip'):need(states.get(key)=='run');states[key]=action
            else:need(action=='output'and key in states and type(row.get('Output'))is str)
        elif action in ('pass','fail','skip'):
            if action=='pass':need(all(v in ('pass','skip')for k,v in states.items()if k[0]==package))
            if action=='skip':need(not any(k[0]==package for k in states))
            terminals[package]=action
        else:need(action=='output'and type(row.get('Output'))is str)
        if action=='output':outputs[package].append(row['Output'])
    need(PACKAGE in begun)
    required_sets={key:[]for key in ('passed','failed','skipped','unfinished','notStarted')}
    for package,items in required.items():
        for name in items:
            state=states.get((package,name));bucket={'pass':'passed','fail':'failed','skip':'skipped','run':'unfinished','pause':'unfinished',None:'notStarted'}[state]
            required_sets[bucket].append(package+'::'+name)
    need(sum(map(len,required_sets.values()))==688)
    for items in required_sets.values():items.sort()
    unfinished=sorted(p+'::'+n for (p,n),state in states.items()if state in ('run','pause'));need(len(unfinished)<=4096)
    failed=sorted(p+'::'+n for (p,n),state in states.items()if state=='fail');need(len(failed)<=4096)
    skipped=sorted(p+'::'+n for (p,n),state in states.items()if state=='skip');need(len(skipped)<=4096)
    structurally_complete=begun==packages and set(terminals)==packages and all(v=='pass'for v in terminals.values()) and all(v=='pass'for v in states.values()) and len(required_sets['passed'])==688
    strict=None
    if structurally_complete:strict=checker.events(raw,required) # actual original strict gate, no exception-to-pass adapter
    if go_exit==0:need(begun==packages and set(terminals)==packages and all(v in ('pass','skip')for v in terminals.values()) and all(v in ('pass','skip')for v in states.values()))
    text_by_package={p:''.join(parts)for p,parts in outputs.items()};stderr_text=stderr.decode('utf8','strict')
    race_warning=any('WARNING: DATA RACE'in text for text in text_by_package.values())or'WARNING: DATA RACE'in stderr_text
    accepted=go_exit==0 and strict is not None and stderr==b'' and not race_warning
    return {'fullGoAccepted':accepted,'normalStrictEventsAccepted':strict is not None,'normalStrictEventsReport':strict,
        'requiredCounts':{key:len(items)for key,items in required_sets.items()},'requiredNames':required_sets,
        'observedSemanticStates':len(states),'allUnfinishedNames':unfinished,'allFailedNames':failed,'allSkippedNames':skipped,
        'packageStates':{p:terminals.get(p,'UNFINISHED'if p in begun else'NOT_STARTED')for p in sorted(packages)},
        'capacityCaseState':states.get((PACKAGE,TOP),'NOT_STARTED'),'packageTimeoutObserved':{p:'panic: test timed out after 3m0s'in text_by_package[p]for p in sorted(packages)},
        'dataRaceWarningObserved':race_warning,'originalGoExit':go_exit,'nonRequiredStatesRetainedInOriginalJSON':True}

def verify_resource(raw):
    need(type(raw)is bytes and 0<len(raw)<=65536);v=decode(raw)
    need(exact(v,['schema','diagnosticMode','scope','startedMonotonicNs','finishedMonotonicNs','observations']))
    need(v['schema']=='chengwang.capacity-profile-resources/v1'and v['diagnosticMode']=='FULL_CONTRACTS'and v['scope']=='CAPTURE_PROCESS_AND_KERNEL_CGROUP_AGGREGATES_NOT_PER_TEST_NOT_ATOMIC')
    need(integer(v['startedMonotonicNs'])and integer(v['finishedMonotonicNs'],v['startedMonotonicNs']))
    need(exact(v['observations'],RESOURCE_SCOPES))
    unavailable=('CGROUP_V2_UNAVAILABLE','CGROUP_V2_NOT_MAPPED','CGROUP_READ_UNAVAILABLE','CGROUP_FILE_UNAVAILABLE')
    for name,row in v['observations'].items():
        need(exact(row,['scope','value','reason'])and row['scope']==RESOURCE_SCOPES[name]);data=row['value'];reason=row['reason']
        if data is None:need(reason in (('VALUE_UNAVAILABLE',)if name in ('cpuCount','affinityCPUs')else('KERNEL_VALUE_UNAVAILABLE',)if name=='procStatCPU'else unavailable));continue
        if name=='cpuCount':need(reason=='NONE'and integer(data,1,1<<20))
        elif name=='affinityCPUs':need(reason=='NONE'and type(data)is list and 1<=len(data)<=4096 and all(integer(n,0,1<<20)for n in data)and data==sorted(set(data)))
        elif name=='procStatCPU':need(reason=='NONE'and exact(data,['user','system','idle','iowait','steal'])and all(integer(n)for n in data.values()))
        elif name=='cgroupCPUMax':
            need(reason=='NONE'and exact(data,['quotaMicros','periodMicros','unlimited'])and type(data['unlimited'])is bool and integer(data['periodMicros'],1))
            need((data['quotaMicros']is None)==data['unlimited']and(data['quotaMicros']is None or integer(data['quotaMicros'],1)))
        else:
            need(exact(data,CPU_STAT_FIELDS)and any(n is not None for n in data.values())and all(n is None or integer(n)for n in data.values()))
            need(reason==('NONE'if all(n is not None for n in data.values())else'PARTIAL_FIELDS'))
    return v

def verify_raw(raw,commit,diagnostic_mode='SINGLE_CASE',sources=None):
    need(diagnostic_mode in ('SINGLE_CASE','FULL_CONTRACTS'));full=diagnostic_mode=='FULL_CONTRACTS'
    public=PUBLIC+(RESOURCE_NAMES if full else())
    need(set(raw)==set(public) and sum(map(len,raw.values()))<=64<<20)
    e=decode(raw['execution.json']);need(exact(e,['schema','sourceCommit','versionExit','formatExit','goExit','topExit','cumExit','profileCaptureComplete','production']+(['diagnosticMode']if full else[])))
    need(e['schema']==('chengwang.capacity-profile-execution/v2'if full else'chengwang.capacity-profile-execution/v1') and e['sourceCommit']==commit and e['production'] is False)
    if full:need(e['diagnosticMode']=='FULL_CONTRACTS')
    need(all(integer(e[k],-128,255) for k in ('versionExit','formatExit','goExit','topExit','cumExit')) and e['versionExit']==e['topExit']==e['cumExit']==0)
    need(e['profileCaptureComplete'] is True and raw['go-version.txt']==b'go version go1.23.12 linux/amd64\n')
    before,after=decode(raw['host-before.json']),decode(raw['host-after.json']);need(before==after and exact(before,['networkNamespace','mountNamespace','pidNamespace','resolvSHA256']))
    box=decode(raw['sandbox.json']);need(exact(box,['schema','uid','gid','effectiveCaps','noNewPrivileges','interfaces','defaultRoutes','environmentKeys',
        'sourceAliasReadOnly','goRootReadOnly','goRoot','networkNamespace','mountNamespace','pidNamespace','production']))
    need(box['schema']=='chengwang.capacity-profile-sandbox/v1' and type(box['uid']) is type(box['gid']) is int and box['uid']==box['gid']==10001)
    need(box['effectiveCaps']=='0000000000000000' and box['noNewPrivileges'] is True and box['interfaces']==['lo'] and box['defaultRoutes']=={'ipv4':[],'ipv6':[]})
    need(box['environmentKeys']==sorted(ENV+(['CHENGWANG_CAPACITY_PROFILE_MODE']if full else[])) and box['sourceAliasReadOnly'] is box['goRootReadOnly'] is True and box['production'] is False)
    for key,kind in [('networkNamespace','net'),('mountNamespace','mnt'),('pidNamespace','pid')]:
        need(re.fullmatch(kind+r':\[[0-9]+\]',box[key]) is not None and re.fullmatch(kind+r':\[[0-9]+\]',before[key]) is not None and box[key]!=before[key])
    need(re.fullmatch('[a-f0-9]{64}',before['resolvSHA256']) is not None)
    need(type(box['goRoot']) is str and Path(box['goRoot']).is_absolute() and '..' not in Path(box['goRoot']).parts)
    state=decode(raw['profile-state.json']);need(exact(state,['schema','sourceCommit','stopReason','startedAt','stoppedAt','durationNanoseconds','profileBytes','profileSHA256',
        'writerFailed','limitReached','syncSucceeded','closeSucceeded','complete','timerSeconds','testTimeoutSeconds']+(['diagnosticMode']if full else[])))
    timer=120 if full else 60
    need(state['schema']==('chengwang.capacity-cpu-profile-state/v2'if full else'chengwang.capacity-cpu-profile-state/v1') and state['sourceCommit']==commit and state['stopReason'] in ('TIMER_'+str(timer)+'_SECONDS','M_RUN_RETURNED'))
    if full:need(state['diagnosticMode']=='FULL_CONTRACTS')
    need(state['writerFailed'] is state['limitReached'] is False and state['syncSucceeded'] is state['closeSucceeded'] is state['complete'] is True)
    need(type(state['timerSeconds']) is type(state['testTimeoutSeconds']) is int and state['timerSeconds']==timer and state['testTimeoutSeconds']==180)
    need(integer(state['durationNanoseconds'],1,180000000000))
    if state['stopReason']=='TIMER_'+str(timer)+'_SECONDS':need(state['durationNanoseconds']>=timer*1000000000)
    for key in ('startedAt','stoppedAt'):need(type(state[key]) is str and re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z',state[key]) is not None)
    need(datetime.datetime.fromisoformat(state['stoppedAt'].replace('Z','+00:00'))>=datetime.datetime.fromisoformat(state['startedAt'].replace('Z','+00:00')))
    profile=decode(raw['cpu-profile.json']);need(exact(profile,['schema','sourceCommit','bytes','sha256','dataBase64','profileStateSHA256']))
    need(profile['schema']=='chengwang.capacity-cpu-profile-bytes/v1' and profile['sourceCommit']==commit and type(profile['dataBase64']) is str)
    binary=base64.b64decode(profile['dataBase64'],validate=True)
    need(base64.b64encode(binary).decode()==profile['dataBase64'] and integer(profile['bytes'],1,8<<20) and integer(state['profileBytes'],1,8<<20) and len(binary)==profile['bytes']==state['profileBytes'])
    need(profile['sha256']==state['profileSHA256']==sha(binary) and profile['profileStateSHA256']==sha(raw['profile-state.json']))
    shape=profile_shape(binary,diagnostic_mode)
    rows=[decode(line) for line in raw['commands.jsonl'].splitlines()];need(len(rows)==15)
    go=str(Path(box['goRoot'])/'bin/go')
    expected=[('VERSION',[go,'version'],'versionExit'),('FORMAT',[str(Path(box['goRoot'])/'bin/gofmt'),'-d',*(FULL_FMT if full else CAPACITY_FMT)],'formatExit'),
        ('GO_TEST',[go,*(FULL_GO_ARGS if full else GO_ARGS)],'goExit'),('PPROF_TOP',[go,'tool','pprof','-symbolize=local','-top',PRIVATE+'/cpu.pprof'],'topExit'),
        ('PPROF_CUM',[go,'tool','pprof','-symbolize=local','-top','-cum',PRIVATE+'/cpu.pprof'],'cumExit')]
    previous=0
    for i,(kind,argv,exitkey) in enumerate(expected):
        group=rows[3*i:3*i+3]
        for j,row in enumerate(group):
            need(exact(row,['seq','event','class','argv','pid','exitCode','monotonicNs']) and type(row['seq']) is int and row['seq']==3*i+j+1)
            need(row['class']==kind and row['argv']==argv and integer(row['monotonicNs'],previous));previous=row['monotonicNs']
        need([r['event'] for r in group]==['START_INTENT','STARTED','WAIT_RETURNED'])
        need(group[0]['pid'] is group[0]['exitCode'] is None and integer(group[1]['pid'],2) and group[1]['exitCode'] is None)
        need(integer(group[2]['pid'],2,(1<<31)-1) and group[2]['pid']==group[1]['pid'] and type(group[2]['exitCode']) is int and group[2]['exitCode']==e[exitkey])
    for name in ('pprof-top.txt','pprof-cum.txt'):
        value=raw[name].decode('utf8','strict');need(value.strip() and 'flat'in value and 'cum'in value)
    if full:
        checker,required,binding=full_source_contract(sources,decode(raw['source-before.json']))
        summary=full_events(raw['capacity.json'],required,checker,e['goExit'],raw['capacity.stderr'])
        resource_before,resource_after=verify_resource(raw['resource-before.json']),verify_resource(raw['resource-after.json'])
        need(resource_before['finishedMonotonicNs']<=rows[6]['monotonicNs']<=rows[8]['monotonicNs']<=resource_after['startedMonotonicNs'])
        return {'schema':'chengwang.capacity-profile-verification/v2','diagnosticMode':'FULL_CONTRACTS',
            'scope':'FULL_SIX_PACKAGE_RACE_DIAGNOSIS_WITH_MIHOMODEPLOY_ONLY_CPU_WINDOW_NOT_PRODUCT_ACCEPTANCE',
            'sourceCommit':commit,'captureVerified':True,**summary,'normalSourceBinding':binding,
            'formatClean':e['formatExit']==0 and raw['gofmt.patch']==raw['gofmt.stderr']==b'',
            'profile':shape,'profileSHA256':sha(binary),'profileProcessPackage':PACKAGE,'profileTimerSeconds':120,
            'profileStopReason':state['stopReason'],'profileMeasuredDurationNanoseconds':state['durationNanoseconds'],
            'wholeSixPackageCPUProfileProven':False,'wholeTestDurationProfileProven':False,
            'resources':{'before':resource_before,'after':resource_after,'window':'BEFORE_AFTER_GO_CLI_INCLUDING_COMPILATION_AND_SIX_PACKAGES_NOT_PROFILE_WINDOW',
                'sameCgroupAcrossObservationsIndependentlyProven':False,'resourceCauseProven':False},
            'inputSHA256':{p:sha(v)for p,v in raw.items()},'pprofNumericRecomputeProven':False,
            'nativeKernelExecuted':False,'normal13WorkflowAccepted':False,'wholeCIPass':False,'production':False}
    events=[decode(line) for line in raw['capacity.json'].splitlines()]
    need(events and all(type(v) is dict and set(v)<={'Time','Action','Package','Test','Elapsed','Output'} and v.get('Package')==PACKAGE and v.get('Action') in ('start','run','pass','fail','output') for v in events))
    begun=False;ended=False;test_state=None
    for row in events:
        need(not ended and type(row.get('Time')) is str and row['Time'].endswith('Z'))
        datetime.datetime.fromisoformat(row['Time'].replace('Z','+00:00'))
        if 'Elapsed' in row:need(type(row['Elapsed']) in (int,float) and math.isfinite(row['Elapsed']) and row['Elapsed']>=0)
        action=row['Action'];name=row.get('Test')
        if action=='start':need(not begun and name is None);begun=True;continue
        need(begun)
        if name is not None:
            need(name==TOP)
            if action=='run':need(test_state is None);test_state='run'
            elif action in ('pass','fail'):need(test_state=='run');test_state=action
            else:need(action=='output' and test_state is not None and type(row.get('Output')) is str)
        elif action in ('pass','fail'):
            if action=='pass':need(test_state=='pass')
            ended=True
        else:need(action=='output' and type(row.get('Output')) is str)
    need(ended)
    test_events=[v for v in events if v.get('Test') is not None];need(all(v['Test']==TOP for v in test_events))
    need(sum(v['Action']=='run' for v in test_events)==1 and not any(v['Action']=='skip' for v in events))
    terminal=[v['Action'] for v in events if v.get('Test') is None and v['Action'] in ('pass','fail')];need(len(terminal)==1)
    passed=sum(v['Action']=='pass' for v in test_events);failed=sum(v['Action']=='fail' for v in test_events);need(passed<=1 and failed<=1 and not(passed and failed))
    case_pass=e['goExit']==0 and passed==1 and terminal==['pass'] and failed==0
    need((e['goExit']==0)==case_pass)
    text=''.join(v.get('Output','') for v in events)
    for name in ('pprof-top.txt','pprof-cum.txt'):
        value=raw[name].decode('utf8','strict');need(value.strip() and 'flat' in value and 'cum' in value)
    return {'schema':'chengwang.capacity-profile-verification/v1','scope':'CPU_DIAGNOSIS_OF_ORIGINAL_STRUCTURAL_CAPACITY_TEST_NOT_RECOVERY_OR_PRODUCTION',
        'sourceCommit':commit,'captureVerified':True,'originalCasePassed':case_pass,'originalGoExit':e['goExit'],
        'testRun':1,'testPass':passed,'testFailureEvents':failed,'packageTerminal':terminal[0],
        'packageTimeoutObserved':'panic: test timed out after 3m0s' in text,'dataRaceWarningObserved':'WARNING: DATA RACE' in text,
        'formatClean':e['formatExit']==0 and raw['gofmt.patch']==raw['gofmt.stderr']==b'',
        'profile':shape,'profileSHA256':sha(binary),'inputSHA256':{p:sha(v) for p,v in raw.items()},
        'pprofNumericRecomputeProven':False,
        'nativeKernelExecuted':False,'wholeCIPass':False,'production':False}

def main():
    p=argparse.ArgumentParser();p.add_argument('mode',choices=['host','source','verify']);p.add_argument('--out',type=Path);p.add_argument('--repo',type=Path);p.add_argument('--source-commit');p.add_argument('--evidence',type=Path);p.add_argument('--report',type=Path);p.add_argument('--diagnostic-mode',choices=['SINGLE_CASE','FULL_CONTRACTS'],default='SINGLE_CASE');a=p.parse_args()
    need(os.name=='posix')
    if a.mode=='host':write(a.out,encoded(host()));return
    if a.mode=='source':write(a.out,encoded(source_snapshot(a.repo,a.source_commit)));return
    public=PUBLIC+(RESOURCE_NAMES if a.diagnostic_mode=='FULL_CONTRACTS'else())
    need(set(v.name for v in a.evidence.iterdir())==set(public))
    need(a.report.is_absolute() and not a.report.is_relative_to(a.repo) and not a.report.is_relative_to(a.evidence))
    raw={name:read(a.evidence/name,12<<20 if name=='cpu-profile.json' else 64<<20 if name=='capacity.json' else 2<<20) for name in public}
    sources=source_snapshot(a.repo,a.source_commit)
    need(raw['source-before.json']==raw['source-after.json']==encoded(sources))
    normal_sources=None
    if a.diagnostic_mode=='FULL_CONTRACTS':
        checker=load_normal_checker();normal_sources={p:read(a.repo/p,1<<20)for p in checker.FILES}
    report=verify_raw(raw,a.source_commit,a.diagnostic_mode,normal_sources)
    need(all(read(a.evidence/name,len(value))==value for name,value in raw.items()) and source_snapshot(a.repo,a.source_commit)==sources)
    report['sourceManifestSHA256']=sha(encoded(sources));report['sourceGitVerified']=True
    write(a.report,encoded(report))
    if a.diagnostic_mode=='FULL_CONTRACTS':print('CAPACITY_PROFILE_EVIDENCE=VERIFIED diagnostic_mode=FULL_CONTRACTS full_go_accepted='+str(report['fullGoAccepted']).lower()+' not_whole_ci=true')
    else:print('CAPACITY_PROFILE_EVIDENCE=VERIFIED original_case_passed='+str(report['originalCasePassed']).lower()+' not_whole_ci=true')
if __name__=='__main__':
    try:main()
    except Exception:raise SystemExit('CAPACITY_PROFILE_EVIDENCE=REJECTED raw_error_suppressed=true') from None
