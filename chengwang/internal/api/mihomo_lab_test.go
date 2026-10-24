package api

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"chengwang/internal/adapter/mihomo"
	"chengwang/internal/authz"
	"chengwang/internal/mihomodeploy"
)

// These are MODEL backend/HTTP-boundary tests. Fake headers, hashes, results
// and observations do not establish current authentication, WAL ownership,
// independent approval, actual process/transport effects or head provenance.
const labAPIModelID = "labop_11111111111111111111111111111111"
const labAPIModelToken = "Bearer MODEL_LAB_TOKEN"
func labAPIModelHash(c string) string { return strings.Repeat(c,64) }
func labAPIModelTime() time.Time { return time.Date(2026,1,2,3,4,5,0,time.UTC) }
func labAPIModelView() mihomodeploy.LabDeploymentView {
	return mihomodeploy.LabDeploymentView{Schema:mihomodeploy.LabDeploymentViewSchema,Boundary:mihomodeploy.LabBackendBoundary,
		OperationID:labAPIModelID,Phase:"PLANNED",Revision:3,PlanSHA256:labAPIModelHash("2"),CandidateRecordSHA256:labAPIModelHash("3"),
		CandidateConfigSHA256:labAPIModelHash("5"),PreviousHeadSHA256:labAPIModelHash("4"),HeadSHA256:labAPIModelHash("4"),HeadGeneration:1,ExpiresAt:labAPIModelTime()}
}
func labAPIModelHead() mihomodeploy.LabHeadView {
	return mihomodeploy.LabHeadView{Schema:mihomodeploy.LabHeadViewSchema,Boundary:mihomodeploy.LabBackendBoundary,Revision:3,Generation:1,
		HeadSHA256:labAPIModelHash("4"),ArtifactRecordSHA256:labAPIModelHash("6"),ConfigSHA256:labAPIModelHash("7"),VerificationSHA256:labAPIModelHash("8"),VerifiedAt:labAPIModelTime()}
}
func labAPIModelCandidates() mihomodeploy.LabCandidateListView {
	return mihomodeploy.LabCandidateListView{Schema:mihomodeploy.LabCandidateListViewSchema,Boundary:mihomodeploy.LabBackendBoundary,
		Candidates:[]mihomodeploy.LabCandidateView{{Name:"local-a",RecordSHA256:labAPIModelHash("1"),ConfigSHA256:labAPIModelHash("2"),SourceSpecSHA256:labAPIModelHash("3"),IsCurrent:true},
			{Name:"local-b",RecordSHA256:labAPIModelHash("4"),ConfigSHA256:labAPIModelHash("5"),SourceSpecSHA256:labAPIModelHash("6")}}}
}
type labAPIModelBackend struct {
	scope authz.ResourceScope
	scopeCalls int
	calls int
	action string
	headers []string
	id string
	create mihomodeploy.LabCreateRequest
	approve mihomodeploy.LabApprovalRequest
	execute mihomodeploy.LabExecuteRequest
	revoke mihomodeploy.LabRevokeRequest
	view mihomodeploy.LabDeploymentView
	head mihomodeploy.LabHeadView
	candidates mihomodeploy.LabCandidateListView
	err error
	mutateHeaders bool
	ctx context.Context
}
func newLabAPIModel() *labAPIModelBackend {
	return &labAPIModelBackend{scope:authz.ResourceScope{TenantID:"MODEL-tenant",SiteID:"MODEL-site",ObjectType:mihomodeploy.LabObjectType,ObjectID:"MODEL-owned",Environment:mihomodeploy.LabEnvironment},
		view:labAPIModelView(),head:labAPIModelHead(),candidates:labAPIModelCandidates()}
}
func (b *labAPIModelBackend) Scope() authz.ResourceScope { b.scopeCalls++;return b.scope }
func (b *labAPIModelBackend) record(ctx context.Context,h []string,id,action string) {
	b.calls++;b.ctx=ctx;b.headers=append([]string(nil),h...);b.id=id;b.action=action
	if b.mutateHeaders && len(h)>0 { h[0]="MODEL_MUTATED_COPY" }
}
func (b *labAPIModelBackend) Create(c context.Context,h []string,r mihomodeploy.LabCreateRequest)(mihomodeploy.LabDeploymentView,error){b.record(c,h,"","create");b.create=r;return b.view,b.err}
func (b *labAPIModelBackend) Inspect(c context.Context,h []string,id string)(mihomodeploy.LabDeploymentView,error){b.record(c,h,id,"inspect");return b.view,b.err}
func (b *labAPIModelBackend) Approve(c context.Context,h []string,id string,r mihomodeploy.LabApprovalRequest)(mihomodeploy.LabDeploymentView,error){b.record(c,h,id,"approve");b.approve=r;return b.view,b.err}
func (b *labAPIModelBackend) Execute(c context.Context,h []string,id string,r mihomodeploy.LabExecuteRequest)(mihomodeploy.LabDeploymentView,error){b.record(c,h,id,"execute");b.execute=r;return b.view,b.err}
func (b *labAPIModelBackend) Revoke(c context.Context,h []string,id string,r mihomodeploy.LabRevokeRequest)(mihomodeploy.LabDeploymentView,error){b.record(c,h,id,"revoke");b.revoke=r;return b.view,b.err}
func (b *labAPIModelBackend) Head(c context.Context,h []string)(mihomodeploy.LabHeadView,error){b.record(c,h,"","head");return b.head,b.err}
func (b *labAPIModelBackend) Candidates(c context.Context,h []string)(mihomodeploy.LabCandidateListView,error){b.record(c,h,"","candidates");return b.candidates,b.err}
type labAPINeverLegacyAuth struct{}
func (labAPINeverLegacyAuth) AuthenticateAuthorizationValues([]string,time.Time)(authz.Principal,error){panic("MODEL legacy authenticator must not replace backend authentication")}
func labAPIRequest(method,path,body string) *http.Request {
	var input io.Reader;if body!="" { input=strings.NewReader(body) }
	r:=httptest.NewRequest(method,path,input);r.RemoteAddr="127.0.0.1:12345";r.Header.Set("Authorization",labAPIModelToken)
	if method==http.MethodPost {r.Header.Set("Content-Type","application/json")};return r
}
func labAPICreateBody() string { return `{"candidateRecordSHA256":"`+labAPIModelHash("3")+`","ttlSeconds":60}` }
func labAPICASBody() string { return `{"planSHA256":"`+labAPIModelHash("2")+`","revision":3}` }
func labAPIRevokeBody() string { return `{"planSHA256":"`+labAPIModelHash("2")+`","revision":3,"reason":"SAFETY_STOP"}` }
func labAPICall(h http.Handler,r *http.Request) *httptest.ResponseRecorder {w:=httptest.NewRecorder();h.ServeHTTP(w,r);return w}
type labAPIBodySpy struct{reader io.Reader;reads,closed int}
func (b *labAPIBodySpy) Read(p []byte)(int,error){b.reads++;if b.reader==nil{return 0,io.EOF};return b.reader.Read(p)}
func (b *labAPIBodySpy) Close()error{b.closed++;return nil}
func labAPITestHandler(b mihomodeploy.LabBackend,writes bool) http.Handler {return New(Options{MihomoLab:b,MihomoLabWritesEnabled:writes,Authn:labAPINeverLegacyAuth{}})}

func TestMihomoLabAPIFixedRoutesForwardOnlyTheirExactRequests(t *testing.T) {
	for _,tc:=range []struct{method,path,body,action string;status int}{
		{"POST",mihomoLabPrefix+"/deployments",labAPICreateBody(),"create",201},
		{"GET",mihomoLabPrefix+"/deployments/"+labAPIModelID,"","inspect",200},
		{"POST",mihomoLabPrefix+"/deployments/"+labAPIModelID+"/approvals",labAPICASBody(),"approve",200},
		{"POST",mihomoLabPrefix+"/deployments/"+labAPIModelID+"/execute",labAPICASBody(),"execute",200},
		{"POST",mihomoLabPrefix+"/deployments/"+labAPIModelID+"/revocations",labAPIRevokeBody(),"revoke",200},
		{"GET",mihomoLabPrefix+"/head","","head",200},{"GET",mihomoLabPrefix+"/candidates","","candidates",200},
	}{b:=newLabAPIModel();w:=labAPICall(labAPITestHandler(b,true),labAPIRequest(tc.method,tc.path,tc.body));if w.Code!=tc.status||b.calls!=1||b.action!=tc.action||b.scopeCalls!=1{t.Fatal("MODEL fixed route did not match backend method")}}
}
func TestMihomoLabAPIOriginalAuthorizationValuesAreDetachedAndLegacyIdentityIsNotSubstituted(t *testing.T) {
	b:=newLabAPIModel();b.mutateHeaders=true;r:=labAPIRequest("POST",mihomoLabPrefix+"/deployments",labAPICreateBody())
	w:=labAPICall(labAPITestHandler(b,true),r)
	if w.Code!=201||len(b.headers)!=1||b.headers[0]!=labAPIModelToken||r.Header.Values("Authorization")[0]!=labAPIModelToken{t.Fatal("original credentials replaced, trimmed or aliased")}
}
func TestMihomoLabAPIDefaultWriteGateRejectsBeforeBodyOrBackendMutation(t *testing.T) {
	for _,path:=range []string{mihomoLabPrefix+"/deployments",mihomoLabPrefix+"/deployments/"+labAPIModelID+"/approvals",mihomoLabPrefix+"/deployments/"+labAPIModelID+"/execute",mihomoLabPrefix+"/deployments/"+labAPIModelID+"/revocations"}{
		b:=newLabAPIModel();r:=labAPIRequest("POST",path,labAPICreateBody());spy:=&labAPIBodySpy{};r.Body=spy
		w:=labAPICall(labAPITestHandler(b,false),r);if w.Code!=503||b.calls!=0||spy.reads!=0{t.Fatal("default writes reached body or backend")}
	}
}
func TestMihomoLabAPINilAndTypedNilBackendsFailClosed(t *testing.T) {
	var typed *labAPIModelBackend
	for _,backend:=range []mihomodeploy.LabBackend{nil,typed}{for _,path:=range []string{mihomoLabPrefix+"/head",mihomoLabPrefix+"/candidates"}{if w:=labAPICall(labAPITestHandler(backend,true),labAPIRequest("GET",path,""));w.Code!=503{t.Fatal("nil backend became available")}}}
}
func TestMihomoLabAPIInvalidFixedScopeCannotReachBackend(t *testing.T) {
	for _,field:=range []string{"tenant","site","object","type","environment"}{b:=newLabAPIModel();switch field{case "tenant":b.scope.TenantID="";case "site":b.scope.SiteID="";case "object":b.scope.ObjectID="../private";case "type":b.scope.ObjectType="router";case "environment":b.scope.Environment="production"}
		w:=labAPICall(labAPITestHandler(b,true),labAPIRequest("GET",mihomoLabPrefix+"/head",""));if w.Code!=503||b.calls!=0{t.Fatal("invalid source scope reached backend")}}
}
func TestMihomoLabAPIMissingMalformedDuplicateCredentialsNeverReachBackend(t *testing.T) {
	for _,values:=range [][]string{nil,{""},{"Basic MODEL"},{"bearer MODEL"},{"Bearer MODEL TOKEN"},{"Bearer A,B"},{labAPIModelToken,labAPIModelToken}}{
		b:=newLabAPIModel();r:=labAPIRequest("POST",mihomoLabPrefix+"/deployments",labAPICreateBody());r.Header.Del("Authorization");for _,v:=range values{r.Header.Add("Authorization",v)};spy:=&labAPIBodySpy{};r.Body=spy
		w:=labAPICall(labAPITestHandler(b,true),r);if w.Code!=401||w.Header().Get("WWW-Authenticate")==""||b.calls!=0||spy.reads!=0{t.Fatal("malformed credentials reached body or backend")}
	}
}
func TestMihomoLabAPITransportUsesActualTLSOrLoopbackNotForwardedClaims(t *testing.T) {
	for _,tlsEnabled:=range []bool{false,true}{b:=newLabAPIModel();r:=labAPIRequest("GET",mihomoLabPrefix+"/head","");r.RemoteAddr="10.0.0.5:123";r.Header.Set("X-Forwarded-Proto","https");r.Header.Set("X-Forwarded-For","127.0.0.1");if tlsEnabled{r.TLS=&tls.ConnectionState{}}
		w:=labAPICall(labAPITestHandler(b,true),r);if tlsEnabled {if w.Code!=200||b.calls!=1{t.Fatal("MODEL TLS metadata rejected")}}else if w.Code!=426||b.calls!=0{t.Fatal("forwarded header impersonated secure transport")}}
}
func TestMihomoLabAPIMethodsAreClosedWithExactAllow(t *testing.T) {
	for _,tc:=range []struct{path,allow string}{{mihomoLabPrefix+"/head","GET"},{mihomoLabPrefix+"/candidates","GET"},{mihomoLabPrefix+"/deployments","POST"},{mihomoLabPrefix+"/deployments/"+labAPIModelID,"GET"},{mihomoLabPrefix+"/deployments/"+labAPIModelID+"/execute","POST"}}{
		b:=newLabAPIModel();w:=labAPICall(labAPITestHandler(b,true),labAPIRequest("DELETE",tc.path,""));if w.Code!=405||w.Header().Get("Allow")!=tc.allow||b.calls!=0{t.Fatal("wrong method reached backend")}}
}
func TestMihomoLabAPIPathAliasesAndQueriesNeverRedirectIntoCommands(t *testing.T) {
	for _,path:=range []string{mihomoLabPrefix+"//head",mihomoLabPrefix+"/./head",mihomoLabPrefix+"/deployments/../head",mihomoLabPrefix+"/head?",mihomoLabPrefix+"/head?scope=production",mihomoLabPrefix+"/%68ead"}{
		b:=newLabAPIModel();w:=labAPICall(labAPITestHandler(b,true),labAPIRequest("GET",path,""));if w.Code!=400||w.Header().Get("Location")!=""||b.calls!=0{t.Fatal("path alias normalized or reached backend")}}
}
func TestMihomoLabAPIReadRoutesHaveNoBodyOrEncoding(t *testing.T) {
	for _,mode:=range []string{"body","length","chunked","encoding"}{b:=newLabAPIModel();r:=labAPIRequest("GET",mihomoLabPrefix+"/head","");spy:=&labAPIBodySpy{};switch mode{case "body":r.Body=spy;case "length":r.ContentLength=1;case "chunked":r.TransferEncoding=[]string{"chunked"};case "encoding":r.Header.Set("Content-Encoding","identity")}
		w:=labAPICall(labAPITestHandler(b,true),r);if w.Code!=400||b.calls!=0||spy.reads!=0{t.Fatal("read route accepted body/encoding")}}
}
func TestMihomoLabAPIWriteMediaEncodingAndTransferFramingAreBounded(t *testing.T) {
	for _,mode:=range []string{"missing","plain","duplicate","charset","parameter","encoding","multi","unsupported","ambiguous"}{b:=newLabAPIModel();r:=labAPIRequest("POST",mihomoLabPrefix+"/deployments",labAPICreateBody());expected:=415
		switch mode{case "missing":r.Header.Del("Content-Type");case "plain":r.Header.Set("Content-Type","text/plain");case "duplicate":r.Header.Add("Content-Type","application/json");case "charset":r.Header.Set("Content-Type","application/json;charset=latin1");case "parameter":r.Header.Set("Content-Type","application/json;profile=x");case "encoding":r.Header.Set("Content-Encoding","gzip");expected=400;case "multi":r.TransferEncoding=[]string{"chunked","chunked"};r.ContentLength=-1;expected=400;case "unsupported":r.TransferEncoding=[]string{"gzip"};r.ContentLength=-1;expected=400;case "ambiguous":r.TransferEncoding=[]string{"chunked"};expected=400}
		w:=labAPICall(labAPITestHandler(b,true),r);if w.Code!=expected||b.calls!=0{t.Fatal("unsupported framing reached backend")}}
	for _,chunked:=range []bool{false,true}{b:=newLabAPIModel();r:=labAPIRequest("POST",mihomoLabPrefix+"/deployments",labAPICreateBody());r.ContentLength=-1;if chunked{r.TransferEncoding=[]string{"chunked"}};if w:=labAPICall(labAPITestHandler(b,true),r);w.Code!=201||b.calls!=1{t.Fatal("valid decoded streaming request rejected")}}
}
func TestMihomoLabAPIStrictDuplicateCaseUnknownAndNestedKeysReject(t *testing.T) {
	if _,ok:=subscriptionObject([]byte(`{"known":{"x":1,"x":2}}`));ok{t.Fatal("nested duplicate tokenizer gate missing")}
	for _,body:=range []string{`{"candidateRecordSHA256":"`+labAPIModelHash("3")+`","ttlSeconds":60,"ttlSeconds":60}`,`{"candidateRecordSHA256":"`+labAPIModelHash("3")+`","ttl\u0053econds":60,"ttlSeconds":60}`,
		`{"CandidateRecordSHA256":"`+labAPIModelHash("3")+`","ttlSeconds":60}`,`{"candidateRecordSHA256":"`+labAPIModelHash("3")+`","ttlSeconds":60,"actor":"admin"}`,`{"candidateRecordSHA256":"`+labAPIModelHash("3")+`","ttlSeconds":{"x":1,"x":2}}`}{
		b:=newLabAPIModel();w:=labAPICall(labAPITestHandler(b,true),labAPIRequest("POST",mihomoLabPrefix+"/deployments",body));if w.Code!=400||b.calls!=0{t.Fatal("strict object rejection failed")}}
}
func TestMihomoLabAPIUTF8SurrogatesAndTrailingValuesAreNotReplaced(t *testing.T) {
	for _,raw:=range []string{`"\ud800"`,`"\udc00"`,`"\ud800\u0041"`,`"\ud800`,"\"bad\n\""}{if mihomoLabJSONStrings([]byte(raw)){t.Fatal("invalid string escape accepted")}}
	for _,raw:=range []string{`"\ud83d\ude00"`,`"\\ud800"`,`"safe"`}{if !mihomoLabJSONStrings([]byte(raw)){t.Fatal("valid JSON string rejected")}}
	for _,body:=range []string{string([]byte{0xff}),labAPICreateBody()+` {}`,`[]`,`null`,strings.Repeat(`{"x":`,10)+`0`+strings.Repeat(`}`,10)}{b:=newLabAPIModel();w:=labAPICall(labAPITestHandler(b,true),labAPIRequest("POST",mihomoLabPrefix+"/deployments",body));if w.Code!=400||b.calls!=0{t.Fatal("invalid JSON reached backend")}}
}
func TestMihomoLabAPITTLAndRequestHashesUseStrictTypesAndCanonicalIntegers(t *testing.T) {
	for _,number:=range []string{"0","301","-0","-1","1.0","1e0","true","null","\"60\"","18446744073709551616"}{b:=newLabAPIModel();body:=`{"candidateRecordSHA256":"`+labAPIModelHash("3")+`","ttlSeconds":`+number+`}`;w:=labAPICall(labAPITestHandler(b,true),labAPIRequest("POST",mihomoLabPrefix+"/deployments",body));if w.Code!=400||b.calls!=0{t.Fatal("invalid TTL reached backend")}}
	for _,hash:=range []string{labAPIModelHash("0"),labAPIModelHash("A"),"PRIVATE_PATH"}{b:=newLabAPIModel();body:=strings.ReplaceAll(labAPICreateBody(),labAPIModelHash("3"),hash);if w:=labAPICall(labAPITestHandler(b,true),labAPIRequest("POST",mihomoLabPrefix+"/deployments",body));w.Code!=400||b.calls!=0{t.Fatal("invalid record hash accepted")}}
}
func TestMihomoLabAPIRevisionCASPreservesFullUint64WithoutFloatConversion(t *testing.T) {
	b:=newLabAPIModel();body:=`{"planSHA256":"`+labAPIModelHash("2")+`","revision":18446744073709551615}`
	w:=labAPICall(labAPITestHandler(b,true),labAPIRequest("POST",mihomoLabPrefix+"/deployments/"+labAPIModelID+"/execute",body))
	if w.Code!=200||b.execute.Revision!=^uint64(0)||b.execute.PlanSHA256!=labAPIModelHash("2"){t.Fatal("CAS numeric precision changed")}
	for _,value:=range []string{"0","-0","3.0","3e0","true","\"3\""}{b:=newLabAPIModel();body:=`{"planSHA256":"`+labAPIModelHash("2")+`","revision":`+value+`}`;if w:=labAPICall(labAPITestHandler(b,true),labAPIRequest("POST",mihomoLabPrefix+"/deployments/"+labAPIModelID+"/execute",body));w.Code!=400||b.calls!=0{t.Fatal("noncanonical revision reached backend")}}
	b=newLabAPIModel();b.view.PlanSHA256=labAPIModelHash("f");if w:=labAPICall(labAPITestHandler(b,true),labAPIRequest("POST",mihomoLabPrefix+"/deployments/"+labAPIModelID+"/execute",labAPICASBody()));w.Code!=503{t.Fatal("returned another plan after requested CAS")}
}
func TestMihomoLabAPIRevokeReasonIsAnEnumNotFreeText(t *testing.T) {
	for _,reason:=range []string{"OPERATOR_REQUESTED","SAFETY_STOP","MODEL_PRIVATE_REASON","safety_stop"}{b:=newLabAPIModel();body:=strings.ReplaceAll(labAPIRevokeBody(),"SAFETY_STOP",reason);w:=labAPICall(labAPITestHandler(b,true),labAPIRequest("POST",mihomoLabPrefix+"/deployments/"+labAPIModelID+"/revocations",body));valid:=reason=="OPERATOR_REQUESTED"||reason=="SAFETY_STOP";if valid{if w.Code!=200||b.revoke.Reason!=reason{t.Fatal("reason not forwarded")}}else if w.Code!=400||b.calls!=0||strings.Contains(w.Body.String(),reason){t.Fatal("free text accepted or reflected")}}
}
func TestMihomoLabAPIOversizedBodiesAreBoundedBeforeBackend(t *testing.T) {
	for _,known:=range []bool{false,true}{b:=newLabAPIModel();r:=labAPIRequest("POST",mihomoLabPrefix+"/deployments",strings.Repeat("x",mihomoLabBodyLimit+1));if !known{r.ContentLength=-1;r.TransferEncoding=[]string{"chunked"}};w:=labAPICall(labAPITestHandler(b,true),r);if w.Code!=413||b.calls!=0{t.Fatal("oversize request reached backend")}}
}
func TestMihomoLabAPICanceledContextCannotReachBackend(t *testing.T) {
	b:=newLabAPIModel();ctx,cancel:=context.WithCancel(context.Background());cancel();r:=labAPIRequest("GET",mihomoLabPrefix+"/head","").WithContext(ctx)
	if w:=labAPICall(labAPITestHandler(b,true),r);w.Code!=503||b.calls!=0{t.Fatal("canceled ingress reached backend")}
}
func TestMihomoLabAPIBackendErrorsHaveClosedSafeStatusMapping(t *testing.T) {
	for _,tc:=range []struct{code mihomodeploy.LabBackendCode;status int}{{mihomodeploy.LabBackendInvalid,400},{mihomodeploy.LabBackendUnauthenticated,401},{mihomodeploy.LabBackendForbidden,403},{mihomodeploy.LabBackendNotFound,404},{mihomodeploy.LabBackendConflict,409},{mihomodeploy.LabBackendUnavailable,503},{mihomodeploy.LabBackendInternal,503},{255,503}}{
		b:=newLabAPIModel();b.err=fmt.Errorf("MODEL_PRIVATE_CAUSE: %w",&mihomodeploy.LabBackendError{Code:tc.code});w:=labAPICall(labAPITestHandler(b,true),labAPIRequest("GET",mihomoLabPrefix+"/head",""));if w.Code!=tc.status||strings.Contains(w.Body.String(),"MODEL_PRIVATE_CAUSE")||!strings.Contains(w.Body.String(),`"result":null`){t.Fatal("backend error leaked or misclassified")}}
}
func TestMihomoLabAPIUnknownAndTypedNilErrorsDoNotClaimUnsentWrites(t *testing.T) {
	var typed *mihomodeploy.LabBackendError
	for _,err:=range []error{errors.New("MODEL_PRIVATE_TRANSPORT"),typed,&mihomodeploy.LabBackendError{Code:mihomodeploy.LabBackendUnavailable,StateMayHaveChanged:true}}{
		b:=newLabAPIModel();b.err=err;w:=labAPICall(labAPITestHandler(b,true),labAPIRequest("POST",mihomoLabPrefix+"/deployments/"+labAPIModelID+"/execute",labAPICASBody()));if w.Code!=503||!strings.Contains(w.Body.String(),`"stateMayHaveChanged":true`)||strings.Contains(w.Body.String(),"MODEL_PRIVATE_TRANSPORT"){t.Fatal("attempted write uncertainty erased")}}
}
func TestMihomoLabAPIInvalidZeroOrProofEscalatedViewsDoNotSerialize(t *testing.T) {
	for _,kind:=range []string{"zero","schema","private","proof","rawphase","id"}{b:=newLabAPIModel();switch kind{case "zero":b.view=mihomodeploy.LabDeploymentView{};case "schema":b.view.Schema="MODEL_PRIVATE_SCHEMA";case "private":b.view.PlanSHA256="MODEL_PRIVATE_CONFIG";case "proof":b.view.Proof.FullPayloadProven=true;case "rawphase":b.view.Phase="ACKNOWLEDGED_SUPPORTED_POSTCONDITION";case "id":b.view.OperationID="arbitrary-model-id"}
		w:=labAPICall(labAPITestHandler(b,true),labAPIRequest("GET",mihomoLabPrefix+"/deployments/"+labAPIModelID,""));if w.Code!=503||strings.Contains(w.Body.String(),"MODEL_PRIVATE"){t.Fatal("unsafe DTO serialized")}}
}
func TestMihomoLabAPIUnknownPreservesArmedNoResultAndOriginalAcknowledgedResult(t *testing.T) {
	for _,transport:=range []*mihomodeploy.LabTransportView{nil,{Result:mihomo.ReloadResult{State:mihomo.ReloadAcknowledged,Dispatched:true,StatusCode:204},RecordedAt:labAPIModelTime(),Origin:"ADAPTER"},{Result:mihomo.ReloadResult{State:mihomo.ReloadUnknown,Dispatched:true},RecordedAt:labAPIModelTime(),Origin:"ADAPTER"}}{
		b:=newLabAPIModel();b.view.Phase="UNKNOWN";b.view.WriteBlocked=true;b.view.Transport=transport;b.view.Observation=&mihomodeploy.LabObservationView{Conclusion:mihomo.LabStableNewProjection,EvidenceSHA256:labAPIModelHash("9"),ObservedAt:labAPIModelTime(),LocalRouteVerified:true}
		w:=labAPICall(labAPITestHandler(b,true),labAPIRequest("GET",mihomoLabPrefix+"/deployments/"+labAPIModelID,""));if w.Code!=200||!strings.Contains(w.Body.String(),`"writeBlocked":true`)||!strings.Contains(w.Body.String(),`"headAdvanced":false`){t.Fatal("UNKNOWN original facts/barrier were replaced")}
		b.view.WriteBlocked=false;if w:=labAPICall(labAPITestHandler(b,true),labAPIRequest("GET",mihomoLabPrefix+"/deployments/"+labAPIModelID,""));w.Code!=503{t.Fatal("matching projection released UNKNOWN")}
	}
}
func TestMihomoLabAPIHistoricalResultsAfterApprovalExpiryRemainVisible(t *testing.T) {
	b:=newLabAPIModel();b.view.Phase="ACKNOWLEDGED";b.view.WriteBlocked=true;b.view.Transport=&mihomodeploy.LabTransportView{Result:mihomo.ReloadResult{State:mihomo.ReloadAcknowledged,Dispatched:true,StatusCode:204},RecordedAt:b.view.ExpiresAt.Add(time.Hour),Origin:"ADAPTER"}
	if w:=labAPICall(labAPITestHandler(b,true),labAPIRequest("GET",mihomoLabPrefix+"/deployments/"+labAPIModelID,""));w.Code!=200||!strings.Contains(w.Body.String(),`"statusCode":204`){t.Fatal("expiry erased actual result")}
}
func TestMihomoLabAPICandidatesDistinguishVerifiedCurrentFromBlockedUnknown(t *testing.T) {
	for _,blocked:=range []bool{false,true}{for current:=0;current<=2;current++{b:=newLabAPIModel();b.candidates.WriteBlocked=blocked;for i:=range b.candidates.Candidates{b.candidates.Candidates[i].IsCurrent=i<current}
		w:=labAPICall(labAPITestHandler(b,true),labAPIRequest("GET",mihomoLabPrefix+"/candidates",""));allowed:=(!blocked&&current==1)||(blocked&&current==0);if allowed {if w.Code!=200{t.Fatal("truthful candidate list rejected")}}else if w.Code!=503{t.Fatal("ambiguous or stale current list accepted")}}}
	for _,kind:=range []string{"nil","count","name","hash","proof"}{b:=newLabAPIModel();switch kind{case "nil":b.candidates.Candidates=nil;case "count":b.candidates.Candidates=b.candidates.Candidates[:1];case "name":b.candidates.Candidates[0].Name="MODEL_PRIVATE_PROFILE";case "hash":b.candidates.Candidates[0].RecordSHA256="MODEL_PRIVATE_FILE";case "proof":b.candidates.Proof.Production=true};w:=labAPICall(labAPITestHandler(b,true),labAPIRequest("GET",mihomoLabPrefix+"/candidates",""));if w.Code!=503||strings.Contains(w.Body.String(),"MODEL_PRIVATE"){t.Fatal("unsafe candidate list serialized")}}
}
func TestMihomoLabAPINoBootstrapReconcileOrArbitraryObjectEndpoint(t *testing.T) {
	for _,path:=range []string{mihomoLabPrefix+"/bootstrap",mihomoLabPrefix+"/reconcile",mihomoLabPrefix+"/deployments/"+labAPIModelID+"/reconcile",mihomoLabPrefix+"/deployments/"+labAPIModelID+"/config"}{b:=newLabAPIModel();w:=labAPICall(labAPITestHandler(b,true),labAPIRequest("POST",path,labAPICreateBody()));if w.Code!=404||b.calls!=0{t.Fatal("unapproved authority route exposed")}}
}
func TestMihomoLabAPISafeHeadShapeAndResponseBudgetExcludePrivateMaterial(t *testing.T) {
	b:=newLabAPIModel();w:=labAPICall(labAPITestHandler(b,true),labAPIRequest("GET",mihomoLabPrefix+"/head",""));var envelope struct{Result map[string]json.RawMessage `json:"result"`};if json.Unmarshal(w.Body.Bytes(),&envelope)!=nil||w.Code!=200||len(envelope.Result)!=13||w.Body.Len()>mihomoLabResponseLimit||w.Header().Get("Cache-Control")!="no-store"{t.Fatal("safe head boundary failed")}
	for _,key:=range []string{"pid","token","yaml","scope","permit","headers"}{if _,ok:=envelope.Result[key];ok{t.Fatal("private capability serialized")}}
	for _,kind:=range []string{"missingPrevious","proof","private"}{b:=newLabAPIModel();switch kind{case "missingPrevious":b.head.Generation=2;case "proof":b.head.Proof.InternetBusinessProven=true;case "private":b.head.VerificationSHA256="MODEL_PRIVATE_EVIDENCE"};w:=labAPICall(labAPITestHandler(b,true),labAPIRequest("GET",mihomoLabPrefix+"/head",""));if w.Code!=503||strings.Contains(w.Body.String(),"MODEL_PRIVATE"){t.Fatal("invalid durable head serialized")}}
	for _,active:=range []string{labAPIModelID,"MODEL_PRIVATE_OPERATION",""}{b:=newLabAPIModel();b.head.ActiveOperationID=&active;w:=labAPICall(labAPITestHandler(b,true),labAPIRequest("GET",mihomoLabPrefix+"/head",""));if active==labAPIModelID{if w.Code!=200||!strings.Contains(w.Body.String(),`"activeOperationId":"`+labAPIModelID+`"`){t.Fatal("actual active operation not discoverable")}}else if w.Code!=503||strings.Contains(w.Body.String(),"MODEL_PRIVATE_OPERATION"){t.Fatal("malformed active operation serialized")}}
	id:=labAPIModelID;head:=labAPIModelHead();head.ActiveOperationID=&id;detached:=detachedMihomoLabHead(head);*detached.ActiveOperationID="MODEL_CHANGED_COPY";if id!=labAPIModelID||head.ActiveOperationID==detached.ActiveOperationID{t.Fatal("active operation response aliases backend")}
}
func TestMihomoLabAPITransportOriginCannotConfuseGateWithAdapter(t *testing.T) {
	for _,valid:=range []bool{false,true}{b:=newLabAPIModel();reason:="FINAL_AUTHORIZATION_REJECTED";b.view.Phase="UNSENT_REJECTED";b.view.Transport=&mihomodeploy.LabTransportView{Result:mihomo.ReloadResult{State:mihomo.ReloadRejected},RecordedAt:labAPIModelTime(),Origin:"SERVICE_GATE",GateReason:&reason};if !valid{b.view.Transport.Result.Dispatched=true;b.view.Transport.Result.StatusCode=401}
		w:=labAPICall(labAPITestHandler(b,true),labAPIRequest("GET",mihomoLabPrefix+"/deployments/"+labAPIModelID,""));if valid{if w.Code!=200{t.Fatal("actual service gate metadata rejected")}}else if w.Code!=503{t.Fatal("gate masqueraded as adapter dispatch")}}
	// MODEL cross-product: a generically legal result is not legal in every
	// phase. In particular, nil cannot erase a rejected attempt and a204 cannot
	// be attached to a plan that has not reached dispatch. This does not attest
	// real process/transport/WAL execution or grant permission to dispatch.
	reason:="SERVICE_CONTEXT_CANCELLED"
	cases:=[]struct{name string;transport *mihomodeploy.LabTransportView;allowed string}{
		{"absent",nil,"PLANNED,APPROVED,PREPARED,REVOKED,INTENT_ARMED,UNKNOWN,MANUAL_REQUIRED"},
		{"ack",&mihomodeploy.LabTransportView{Result:mihomo.ReloadResult{State:mihomo.ReloadAcknowledged,Dispatched:true,StatusCode:204},RecordedAt:labAPIModelTime(),Origin:"ADAPTER"},"ACKNOWLEDGED,COMPLETED,UNKNOWN,MANUAL_REQUIRED"},
		{"adapterUnsent",&mihomodeploy.LabTransportView{Result:mihomo.ReloadResult{State:mihomo.ReloadRejected},RecordedAt:labAPIModelTime(),Origin:"ADAPTER"},"UNSENT_REJECTED,UNKNOWN,MANUAL_REQUIRED"},
		{"response4xx",&mihomodeploy.LabTransportView{Result:mihomo.ReloadResult{State:mihomo.ReloadRejected,Dispatched:true,StatusCode:403},RecordedAt:labAPIModelTime(),Origin:"ADAPTER"},"RESPONSE_REJECTED,UNKNOWN,MANUAL_REQUIRED"},
		{"unknown",&mihomodeploy.LabTransportView{Result:mihomo.ReloadResult{State:mihomo.ReloadUnknown,Dispatched:true},RecordedAt:labAPIModelTime(),Origin:"ADAPTER"},"UNKNOWN,MANUAL_REQUIRED"},
		{"serviceGate",&mihomodeploy.LabTransportView{Result:mihomo.ReloadResult{State:mihomo.ReloadRejected},RecordedAt:labAPIModelTime(),Origin:"SERVICE_GATE",GateReason:&reason},"UNSENT_REJECTED,MANUAL_REQUIRED"},
		{"gateAck",&mihomodeploy.LabTransportView{Result:mihomo.ReloadResult{State:mihomo.ReloadAcknowledged,Dispatched:true,StatusCode:204},RecordedAt:labAPIModelTime(),Origin:"SERVICE_GATE",GateReason:&reason},""},
		{"response5xx",&mihomodeploy.LabTransportView{Result:mihomo.ReloadResult{State:mihomo.ReloadRejected,Dispatched:true,StatusCode:503},RecordedAt:labAPIModelTime(),Origin:"ADAPTER"},""},
	}
	for _,phase:=range []string{"PLANNED","APPROVED","PREPARED","REVOKED","INTENT_ARMED","ACKNOWLEDGED","COMPLETED","UNSENT_REJECTED","RESPONSE_REJECTED","UNKNOWN","MANUAL_REQUIRED"}{for _,item:=range cases{
		b:=newLabAPIModel();b.view.Phase=phase;b.view.Transport=item.transport
		b.view.WriteBlocked=phase=="INTENT_ARMED"||phase=="ACKNOWLEDGED"||phase=="UNKNOWN"||phase=="MANUAL_REQUIRED"||phase=="RESPONSE_REJECTED"
		if phase=="COMPLETED"{b.view.HeadAdvanced=true;b.view.HeadGeneration=2;b.view.HeadSHA256=labAPIModelHash("a");b.view.Observation=&mihomodeploy.LabObservationView{Conclusion:mihomo.LabStableNewProjection,EvidenceSHA256:labAPIModelHash("b"),ObservedAt:labAPIModelTime(),LocalRouteVerified:true}}
		allowed:=strings.Contains(","+item.allowed+",",","+phase+",")
		w:=labAPICall(labAPITestHandler(b,true),labAPIRequest("GET",mihomoLabPrefix+"/deployments/"+labAPIModelID,""))
		if !allowed{if w.Code!=503{t.Fatalf("MODEL inconsistent phase/result accepted: %s/%s",phase,item.name)};continue}
		if w.Code!=200{t.Fatalf("MODEL original transport fact rejected: %s/%s",phase,item.name)}
		var envelope struct{Result struct{Transport *mihomodeploy.LabTransportView `json:"transport"`} `json:"result"`}
		if json.Unmarshal(w.Body.Bytes(),&envelope)!=nil{t.Fatal("MODEL transport response malformed")}
		actual:=envelope.Result.Transport
		if item.transport==nil{if actual!=nil{t.Fatal("MODEL absent result invented")}}else if actual==nil||actual.Result!=item.transport.Result||actual.Origin!=item.transport.Origin||!actual.RecordedAt.Equal(item.transport.RecordedAt)||(actual.GateReason==nil)!=(item.transport.GateReason==nil){t.Fatal("MODEL original result rewritten")}else if actual.GateReason!=nil&&*actual.GateReason!=*item.transport.GateReason{t.Fatal("MODEL gate reason rewritten")}
		if phase=="RESPONSE_REJECTED"{b.view.WriteBlocked=false;if w:=labAPICall(labAPITestHandler(b,true),labAPIRequest("GET",mihomoLabPrefix+"/deployments/"+labAPIModelID,""));w.Code!=503{t.Fatal("MODEL response rejection released unresolved sent-attempt barrier")}}
	}}
}
func TestMihomoLabAPICompletedNeedsSupportedNewObservationRouteAndHeadAdvance(t *testing.T) {
	for _,kind:=range []string{"valid","noObservation","oldProjection","noRoute","sameHead","noAdvance"}{b:=newLabAPIModel();b.view.Phase="COMPLETED";b.view.HeadAdvanced=true;b.view.HeadGeneration=2;b.view.HeadSHA256=labAPIModelHash("a");b.view.Transport=&mihomodeploy.LabTransportView{Result:mihomo.ReloadResult{State:mihomo.ReloadAcknowledged,Dispatched:true,StatusCode:204},RecordedAt:labAPIModelTime(),Origin:"ADAPTER"};b.view.Observation=&mihomodeploy.LabObservationView{Conclusion:mihomo.LabStableNewProjection,EvidenceSHA256:labAPIModelHash("b"),ObservedAt:labAPIModelTime(),LocalRouteVerified:true}
		switch kind{case "noObservation":b.view.Observation=nil;case "oldProjection":b.view.Observation.Conclusion=mihomo.LabStableOldProjection;case "noRoute":b.view.Observation.LocalRouteVerified=false;case "sameHead":b.view.HeadSHA256=b.view.PreviousHeadSHA256;case "noAdvance":b.view.HeadAdvanced=false}
		w:=labAPICall(labAPITestHandler(b,true),labAPIRequest("GET",mihomoLabPrefix+"/deployments/"+labAPIModelID,""));if kind=="valid"{if w.Code!=200{t.Fatal("MODEL consistent supported completion rejected")}}else if w.Code!=503{t.Fatal("204 or phase alone manufactured completion")}}
}
