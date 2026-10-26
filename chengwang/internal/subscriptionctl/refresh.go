package subscriptionctl

import (
	"context"
	"errors"
	"time"

	"chengwang/internal/authn"
	"chengwang/internal/authz"
	"chengwang/internal/subscription"
)

const refreshPollInterval = 5 * time.Second
const refreshStoreRetryInitial = 10 * time.Millisecond
const refreshStoreRetryMaximum = 5 * time.Second
const refreshStoreRetryBurst = 3

func (s *Service) setRefreshStoragePending(count uint32,next time.Time){s.refreshStorageMu.Lock();s.refreshStoragePending=true;s.refreshStorageRetryCount=count;s.refreshStorageNextRetryAt=next.UTC();s.refreshStorageMu.Unlock()}
func (s *Service) clearRefreshStoragePending(){s.refreshStorageMu.Lock();s.refreshStoragePending=false;s.refreshStorageRetryCount=0;s.refreshStorageNextRetryAt=time.Time{};s.refreshStorageMu.Unlock()}
func (s *Service) refreshStorageView(v subscription.RefreshView)subscription.RefreshView{s.refreshStorageMu.RLock();defer s.refreshStorageMu.RUnlock();v.StoragePending=s.refreshStoragePending;v.StorageRetryCount=s.refreshStorageRetryCount;v.StorageNextRetryAt=s.refreshStorageNextRetryAt;return v}

// retryRefreshStoreStage retries only one local sidecar persistence call. The
// closure must retain the exact arguments and opaque lease; callers must not
// include fetch, import, domain-store mutation, or audit side effects.
func (s *Service) retryRefreshStoreStage(ctx context.Context,stage string,operation func()error)error{
	delay:=refreshStoreRetryInitial;failures:=uint32(0)
	defer s.clearRefreshStoragePending()
	for{call:=s.refreshStoreCall;var err error;if call==nil{err=operation()}else{err=call(stage,operation)};if err==nil||!subscription.IsCommitNotCommitted(err){return err};if failures<^uint32(0){failures++};if failures>refreshStoreRetryBurst{delay*=2;if delay>refreshStoreRetryMaximum{delay=refreshStoreRetryMaximum}};s.setRefreshStoragePending(failures,s.now().UTC().Add(delay));if ctlCanceled(ctx){return ctlError(CodeCanceled,false)};wait:=s.refreshRetryWait;if wait==nil||!wait(ctx,delay){return ctlError(CodeCanceled,false)}}
}

func refreshIdentityError(err error) error {
	if errors.Is(err, authn.ErrSnapshotUnavailable) || errors.Is(err, authn.ErrSnapshotStale) || errors.Is(err, authn.ErrSnapshotClock) { return ctlError(CodeUnavailable, false) }
	return ctlError(CodeForbidden, false)
}

func refreshPrincipalAllowsSource(principal authz.Principal, scope authz.ResourceScope, sourceID string) bool {
	if principal.ID == "" || principal.TenantID != scope.TenantID || principal.BreakGlassEligible || len(principal.Roles) != 1 || principal.Roles[0] != authz.RoleSubscriptionRefresher || len(principal.AllowedScopes) == 0 || !ctlSource.MatchString(sourceID) { return false }
	found := false
	for _, grant := range principal.AllowedScopes {
		if grant.TenantID != scope.TenantID || grant.SiteID != scope.SiteID || grant.Environment != scope.Environment || grant.ObjectType != "subscription-source" || !ctlSource.MatchString(grant.ObjectID) { return false }
		found = found || grant.ObjectID == sourceID
	}
	return found
}

func exactRefreshPrincipal(principal authz.Principal, scope authz.ResourceScope, bindings []subscription.RefreshBinding) bool {
	if principal.ID == "" || principal.TenantID != scope.TenantID || principal.BreakGlassEligible || len(principal.Roles) != 1 || principal.Roles[0] != authz.RoleSubscriptionRefresher || len(principal.AllowedScopes) == 0 { return false }
	wanted := make(map[string]bool,len(bindings)); for _,b:=range bindings{wanted[b.SourceID]=true};granted:=map[string]bool{}
	for _,g:=range principal.AllowedScopes{if g.TenantID!=scope.TenantID||g.SiteID!=scope.SiteID||g.Environment!=scope.Environment||g.ObjectType!="subscription-source"||!wanted[g.ObjectID]||granted[g.ObjectID]{return false};granted[g.ObjectID]=true}
	return len(granted)==len(wanted)
}

func (s *Service) refreshPrincipalCurrent(principal authz.Principal, sourceID string) bool {
	if principal.ID != s.config.RefreshIdentityID { return false }
	provider, ok := s.config.Policies.(RefreshPolicyProvider); if !ok || ctlNil(provider) { return false }
	bindings, err := provider.RefreshBindings(); if err != nil || len(bindings) == 0 || len(bindings) > subscription.MaxSources { return false }
	found := false; for _, binding := range bindings { found = found || binding.SourceID == sourceID }
	return found && exactRefreshPrincipal(principal, s.config.Scope, bindings)
}

// ensureRefreshCheckpoint binds the sidecar epoch to an acknowledged command
// in the strict subscription-store/v1 wire format. A one-store restore changes
// one side of this comparison and is rejected. Rolling every trusted local
// anchor back together is intentionally outside this local-only guarantee.
func (s *Service) ensureRefreshCheckpoint(ctx context.Context, principal authz.Principal, bindings []subscription.RefreshBinding) error {
	epoch, sidecarID, previousID, ready, err := s.config.RefreshStore.Checkpoint(); if err != nil { return ctlMap(err,false) }
	mainID, mainEpoch, found, err := s.config.Store.LatestRefreshCheckpoint(s.scope); if err != nil { return ctlMap(err,false) }
	if found {
		if mainEpoch==epoch { if ready&&sidecarID!=mainID{return ctlError(CodeConflict,false)};if !ready{err=s.retryRefreshStoreStage(ctx,"checkpoint",func()error{return s.config.RefreshStore.FinalizeCheckpoint(epoch,mainID)});if err!=nil{return ctlMap(err,false)}};return nil }
		if ready||previousID==""||previousID!=mainID{return ctlError(CodeConflict,false)}
	}
	if !found&&previousID!=""||ready || len(bindings)==0 { return ctlError(CodeConflict,false) }
	b:=bindings[0]
	identity,err:=s.config.Store.ControlIdentity(s.scope,principal.ID,"refresh_checkpoint_"+epoch[:32],[]byte("refresh-checkpoint-v3:"+epoch));if err!=nil{return ctlMap(err,false)}
	command:=subscription.ControlCommand{ID:identity.ID,Scope:s.scope,ActorID:identity.ActorID,OwnerID:principal.ID,CoreKey:identity.CoreKey,KeyDigest:identity.KeyDigest,Fingerprint:identity.Fingerprint,Kind:string(Fetch),SourceID:b.SourceID,ExpectedRevision:b.ApprovalSourceRevision}
	prepared,err:=s.appendAudit(command,nil);if err!=nil{return err};command.PreparedAt,command.PreparedAuditHash=prepared.OccurredAt,prepared.Hash
	created,err:=s.config.Store.RecordControlPrepared(command);if err!=nil{return ctlMap(err,false)}
	if !created{return ctlError(CodeConflict,true)}
	result:=subscription.ControlResult{SourceID:b.SourceID,Revision:b.ApprovalSourceRevision,State:"failed",Code:string(CodeUnavailable),ReferenceID:"refresh-epoch-"+epoch,CompletedAt:s.now().UTC()}
	if result.CompletedAt.Before(command.PreparedAt){result.CompletedAt=command.PreparedAt}
	if err=s.config.Store.RecordControlResult(s.scope,command.ID,result);err!=nil{return ctlMap(err,true)};command.Result=&result
	if err=s.completeAudit(command);err!=nil{return err}
	if err=s.retryRefreshStoreStage(ctx,"checkpoint",func()error{return s.config.RefreshStore.FinalizeCheckpoint(epoch,command.ID)});err!=nil{return ctlMap(err,true)}
	return nil
}

// validateRefreshCommandBindings reconstructs automated classification only
// from the issuer-bound sidecar mapping. It never trusts Command.Automated,
// which is intentionally absent from the strict main-store wire format.
func (s *Service) validateRefreshCommandBindings(ctx context.Context,now time.Time) error {
	var views []subscription.RefreshView;err:=s.retryRefreshStoreStage(ctx,"observe",func()error{var e error;views,e=s.config.RefreshStore.Refreshes(s.scope,now);return e});if err!=nil{return ctlMap(err,false)}
	for _,v:=range views{if v.CommandID==""{continue};b:=v.Binding;c:=Command{Kind:Fetch,IdempotencyKey:v.AttemptKey,SourceID:b.SourceID,ExpectedRevision:b.ApprovalSourceRevision,PolicyRevision:b.PolicyRevision,ApprovalID:b.ApprovalID,Automated:true,ApprovalSourceRevision:b.ApprovalSourceRevision,ApprovalMaxAgeSeconds:b.ApprovalTTLSeconds};identity,e:=s.config.Store.ControlIdentity(s.scope,v.CommandOwnerID,v.AttemptKey,ctlMaterial(c));if e!=nil{return ctlMap(e,false)};if identity.ID!=v.CommandID{return ctlError(CodeConflict,false)};record,exists,e:=s.config.Store.ControlCommand(s.scope,v.CommandID);if e!=nil{return ctlMap(e,false)};if !exists{if v.State==subscription.RefreshRunning||v.State==subscription.RefreshUnknown{continue};return ctlError(CodeConflict,false)};if record.ID!=v.CommandID||record.OwnerID!=v.CommandOwnerID||record.Scope!=s.scope||record.SourceID!=v.Binding.SourceID||record.Kind!=string(Fetch)||record.Fingerprint!=identity.Fingerprint{return ctlError(CodeConflict,false)}}
	return nil
}

// ConfigureRefresh resolves the machine identity from the source-owned
// SnapshotManager; no caller-supplied principal can authorize this worker.
func (s *Service) ConfigureRefresh(ctx context.Context) error {
	if s==nil||s.serviceCore==nil||ctlCanceled(ctx)||!s.config.WritesEnabled||ctlNil(s.config.Policies)||s.config.RefreshStore==nil||ctlNil(s.config.RefreshIdentity){return ctlError(CodeUnavailable,false)}
	provider,ok:=s.config.Policies.(RefreshPolicyProvider);if !ok||ctlNil(provider){return ctlError(CodeUnavailable,false)}
	bindings,err:=provider.RefreshBindings();if err!=nil||len(bindings)==0||len(bindings)>subscription.MaxSources{return ctlError(CodeInvalid,false)}
	principal,_,err:=s.config.RefreshIdentity.TrustedPrincipal(s.config.RefreshIdentityID,s.now().UTC());if err!=nil||principal.ID!=s.config.RefreshIdentityID||!exactRefreshPrincipal(principal,s.config.Scope,bindings){return ctlError(CodeForbidden,false)}
	seen:=map[string]bool{}
	for _,b:=range bindings{if seen[b.SourceID]{return ctlError(CodeInvalid,false)};seen[b.SourceID]=true;if err:=s.authorize(ctx,principal,authz.ActionRefreshSubscription,b.SourceID);err!=nil{return err};d,e:=s.config.Policies.Describe(b.ReferenceID);if e!=nil||d.ReferenceID!=b.ReferenceID||d.Revision!=b.PolicyRevision||len(d.Material)==0{return ctlError(CodeApprovalRequired,false)};if _,e=s.config.Store.Source(s.scope,b.SourceID);e!=nil{return ctlMap(e,false)}}
	if err:=s.validateRefreshCommandBindings(ctx,s.now().UTC());err!=nil{return err}
	if err:=s.ensureRefreshCheckpoint(ctx,principal,bindings);err!=nil{return err}
	reconcileAt:=s.now().UTC();if err:=s.retryRefreshStoreStage(ctx,"reconcile",func()error{return s.config.RefreshStore.Reconcile(s.scope,bindings,reconcileAt)});err!=nil{return ctlMap(err,false)};return nil
}

func refreshFailure(code Code)(subscription.RefreshFailure,bool){switch code{case CodeApprovalRequired:return subscription.RefreshFailureApproval,false;case CodeFetchPolicy,CodeLocked:return subscription.RefreshFailurePolicy,false;case CodeFetchUnavailable:return subscription.RefreshFailureTransport,true;case CodeFetchHTTP:return subscription.RefreshFailureHTTP,true;case CodeFetchRateLimited:return subscription.RefreshFailureRate,true;case CodeInvalid:return subscription.RefreshFailureInput,false;case CodeLimit:return subscription.RefreshFailureLimit,false;case CodeConflict:return subscription.RefreshFailureConflict,false;case CodeAuditDegraded:return subscription.RefreshFailureAudit,false;case CodeCommitUnknown:return subscription.RefreshFailureUnknown,false;case CodeCanceled:return subscription.RefreshFailureCanceled,true;case CodeForbidden:return subscription.RefreshFailureForbidden,false;default:return subscription.RefreshFailureUnavailable,true}}

func (s *Service) finishRefresh(ctx context.Context,a subscription.RefreshView,r Receipt,executeErr error)error{
	c:=subscription.RefreshCompletion{AttemptKey:a.AttemptKey,AttemptSequence:a.AttemptSequence,BindingSeal:a.BindingSeal,Fence:a.Fence,CommandID:r.CommandID,CandidateID:r.CandidateID,CandidateDigest:r.CandidateDigest,ResultRevision:r.Revision,AuditRecorded:r.AuditRecorded,StateMayHaveChanged:r.StateMayHaveChanged,Lease:a.Lease}
	if executeErr==nil&&r.Code==""&&r.AuditRecorded&&!r.StateMayHaveChanged{switch r.State{case "committed":c.State=subscription.RefreshCandidateQuarantined;case "noop":c.State=subscription.RefreshSucceededNoop;default:c.State=subscription.RefreshUnknown;c.Failure=subscription.RefreshFailureUnknown;c.StateMayHaveChanged=true}}else if executeErr==nil&&r.Code==""{c.State=subscription.RefreshUnknown;c.Failure=subscription.RefreshFailureUnknown;c.StateMayHaveChanged=true}else{code:=r.Code;var detail *Error;if errors.As(executeErr,&detail){code=detail.Code;c.StateMayHaveChanged=c.StateMayHaveChanged||detail.StateMayHaveChanged};failure,retry:=refreshFailure(code);c.Failure=failure;if c.StateMayHaveChanged||failure==subscription.RefreshFailureUnknown{c.State=subscription.RefreshUnknown;c.Failure=subscription.RefreshFailureUnknown;c.StateMayHaveChanged=true}else if retry{c.State=subscription.RefreshFailed}else{c.State=subscription.RefreshBlocked}}
	completedAt:=s.now().UTC();err:=s.retryRefreshStoreStage(ctx,"complete",func()error{_,e:=s.config.RefreshStore.Complete(s.scope,a.Binding.SourceID,c,completedAt);return e});return ctlMap(err,false)
}

func (s *Service) refreshOnce(ctx context.Context,recovery *subscription.RefreshRecovery)error{
	if s==nil||s.serviceCore==nil||ctlCanceled(ctx){return ctlError(CodeCanceled,false)}
	if !s.refreshBusy.CompareAndSwap(false,true){return ctlError(CodeConflict,false)};defer s.refreshBusy.Store(false)
	refreshAt:=s.now().UTC();var values []subscription.RefreshView;err:=s.retryRefreshStoreStage(ctx,"observe",func()error{var e error;values,e=s.config.RefreshStore.Refreshes(s.scope,refreshAt);return e});if err!=nil{return ctlMap(err,false)}
	for _,v:=range values{
		if ctlCanceled(ctx){return ctlError(CodeCanceled,false)}
		s.capacityMu.Lock()
		var attempt subscription.RefreshView
		var claimed bool
		var e error
		claimAt:=s.now().UTC();e=s.retryRefreshStoreStage(ctx,"claim",func()error{if recovery==nil{capacity,capacityErr:=s.config.Store.Capacity(s.scope);if capacityErr!=nil{return capacityErr};attempt,claimed,e=s.config.RefreshStore.ClaimLive(s.scope,v.Binding.SourceID,capacity,claimAt)}else{attempt,claimed,e=s.config.RefreshStore.ClaimRecovery(s.scope,v.Binding.SourceID,recovery,claimAt)};return e})
		if e!=nil{s.capacityMu.Unlock();return ctlMap(e,false)};if !claimed{s.capacityMu.Unlock();continue}
		b:=attempt.Binding;c:=Command{Kind:Fetch,IdempotencyKey:attempt.AttemptKey,SourceID:b.SourceID,ExpectedRevision:b.ApprovalSourceRevision,PolicyRevision:b.PolicyRevision,ApprovalID:b.ApprovalID,Automated:true,ApprovalSourceRevision:b.ApprovalSourceRevision,ApprovalMaxAgeSeconds:b.ApprovalTTLSeconds}
		receipt,executeErr:=s.executeRefreshLocked(ctx,attempt,c);if ctlCanceled(ctx){s.capacityMu.Unlock();return ctlError(CodeCanceled,false)};e=s.finishRefresh(ctx,attempt,receipt,executeErr);s.capacityMu.Unlock();if e!=nil{return e}
	}
	return nil
}

func (s *Service) RefreshOnce(ctx context.Context)error{return s.refreshOnce(ctx,nil)}
func (s *Service) RecoverRefreshOnce(ctx context.Context)error{return s.refreshOnce(ctx,s.config.RefreshRecovery)}

func (s *Service) RunRefresh(ctx context.Context)error{
	if ctx==nil{return ctlError(CodeInvalid,false)}
	defer s.config.RefreshRecovery.Close()
	if err:=s.RecoverRefreshOnce(ctx);err!=nil{return err}
	s.config.RefreshRecovery.Close()
	timer:=time.NewTimer(refreshPollInterval);defer timer.Stop()
	for{select{case<-ctx.Done():return nil;case<-timer.C:if err:=s.RefreshOnce(ctx);err!=nil{return err};timer.Reset(refreshPollInterval)}}
}

func (s *Service) ListRefreshes(ctx context.Context,p authz.Principal)(RefreshPage,error){if err:=s.authorize(ctx,p,authz.ActionReadSubscription,"");err!=nil{return RefreshPage{},err};values,err:=s.config.RefreshStore.SnapshotRefreshes(s.scope,s.now().UTC());if err!=nil{return RefreshPage{},ctlMap(err,false)};if len(values)>subscription.MaxSources{return RefreshPage{},ctlError(CodeLimit,false)};for i:=range values{values[i]=s.refreshStorageView(values[i])};cap,err:=s.config.Store.Capacity(s.scope);if err!=nil{return RefreshPage{},ctlMap(err,false)};return RefreshPage{Refreshes:values,Total:len(values),Capacity:cap},nil}
func (s *Service) ReadRefresh(ctx context.Context,p authz.Principal,source string)(subscription.RefreshView,error){if !ctlSource.MatchString(source){return subscription.RefreshView{},ctlError(CodeInvalid,false)};if err:=s.authorize(ctx,p,authz.ActionReadSubscription,source);err!=nil{return subscription.RefreshView{},err};v,err:=s.config.RefreshStore.SnapshotRefresh(s.scope,source,s.now().UTC());if err!=nil{return subscription.RefreshView{},ctlMap(err,false)};return s.refreshStorageView(v),nil}
