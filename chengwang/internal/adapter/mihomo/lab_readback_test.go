package mihomo

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Source-derived MODEL responses, not captured Mihomo endpoint output. The
// fixed-source candidate must still be checked by a real pinned kernel in CI.
const labTestGeneral = `{"port":0,"socks-port":0,"redir-port":0,"tproxy-port":0,"mixed-port":18080,"tun":{"enable":false,"device":"","stack":"Mips","dns-hijack":["0.0.0.0:53"],"auto-route":true,"auto-detect-interface":true,"inet4-address":["198.18.0.1/30"],"file-descriptor":0,"recvmsgx":true,"processors-per-channel":1},"tuic-server":{"enable":false,"listen":"","certificate":"","private-key":"","ech-key":"","mux-option":{"brutal":{"enabled":false}}},"ss-config":"","vmess-config":"","authentication":null,"skip-auth-prefixes":null,"lan-allowed-ips":["0.0.0.0/0","::/0"],"lan-disallowed-ips":null,"allow-lan":false,"bind-address":"127.0.0.1","inbound-tfo":false,"inbound-mptcp":false,"mode":"rule","unified-delay":false,"log-level":"silent","ipv6":false,"interface-name":"","routing-mark":0,"geox-url":{"geo-ip":"","mmdb":"","asn":"","geo-site":""},"geo-auto-update":false,"geo-update-interval":24,"geodata-mode":false,"geodata-loader":"memconservative","geosite-matcher":"succinct","tcp-concurrent":false,"find-process-mode":"off","sniffing":false,"global-ua":"clash.meta/v1.19.32","etag-support":true,"keep-alive-idle":0,"keep-alive-interval":0,"disable-keep-alive":false}`
const labTestSecret = "synthetic_lab_readback_private_0123456789"

func labTestSpec(candidate bool) LabExpectedSpec {
	selected:="DIRECT";if candidate{selected="http-a"}
	return LabExpectedSpec{MixedPort:18080,HTTPNames:[]string{"http-a"},Selectors:[]LabSelectorSpec{
		{Name:labReadbackDefault,Members:[]string{selected}},
		{Name:"cw.business.chat",Members:[]string{"http-a","DIRECT"}},
	},Rules:[]LabRuleSpec{{Type:"DomainSuffix",Payload:"example.com",Proxy:"cw.business.chat"},{Type:"Match",Proxy:labReadbackDefault}}}
}
func labTestExpected(t *testing.T,candidate bool) LabExpectation {
	t.Helper();value,err:=NewLabExpectation(labTestSpec(candidate));if err!=nil{t.Fatal("model expectation rejected")};return value
}
func labTestJSON(t *testing.T,value any) []byte { t.Helper();raw,err:=json.Marshal(value);if err!=nil{t.Fatal("model JSON failed")};return raw }
func labTestProxy(name,kind string,udp bool) map[string]any {
	return map[string]any{"type":kind,"id":"11111111-1111-4111-8111-111111111111","history":[]any{},"extra":map[string]any{},"alive":true,"name":name,
		"udp":udp,"uot":false,"xudp":false,"tfo":false,"mptcp":false,"smux":false,"interface":"","routing-mark":0,"provider-name":"","dialer-proxy":""}
}
func labTestSelector(name string,all []string,now string,udp bool) map[string]any {
	m:=labTestProxy(name,"Selector",udp);delete(m,"id");m["all"]=all;m["now"]=now;m["testUrl"]="";m["hidden"]=false;m["icon"]="";m["emptyFallback"]="COMPATIBLE";return m
}
func labTestBodies(t *testing.T,candidate bool) map[string][]byte {
	t.Helper();proxies:=map[string]any{}
	for name,kind:=range map[string]string{"DIRECT":"Direct","REJECT":"Reject","REJECT-DROP":"RejectDrop","COMPATIBLE":"Compatible","PASS":"Pass","PASS-RULE":"PassRule"}{proxies[name]=labTestProxy(name,kind,true)}
	proxies["http-a"]=labTestProxy("http-a","Http",false)
	proxies["cw.business.chat"]=labTestSelector("cw.business.chat",[]string{"http-a","DIRECT"},"http-a",false)
	selected,udp:="DIRECT",true;if candidate{selected,udp="http-a",false};proxies[labReadbackDefault]=labTestSelector(labReadbackDefault,[]string{selected},selected,udp)
	proxies["GLOBAL"]=labTestSelector("GLOBAL",[]string{"DIRECT","REJECT","http-a","cw.business.chat",labReadbackDefault},"DIRECT",true)
	extra:=func()map[string]any{return map[string]any{"disabled":false,"hitCount":uint64(0),"hitAt":"0001-01-01T00:00:00Z","missCount":uint64(0),"missAt":"0001-01-01T00:00:00Z"}}
	rules:=[]any{map[string]any{"index":0,"type":"DomainSuffix","payload":"example.com","proxy":"cw.business.chat","size":-1,"extra":extra()},map[string]any{"index":1,"type":"Match","payload":"","proxy":labReadbackDefault,"size":-1,"extra":extra()}}
	return map[string][]byte{"/version":[]byte(`{"meta":true,"version":"v1.19.32"}`),"/configs":[]byte(labTestGeneral),"/proxies":labTestJSON(t,map[string]any{"proxies":proxies}),"/rules":labTestJSON(t,map[string]any{"rules":rules})}
}
func labTestMutate(t *testing.T,raw []byte,fn func(map[string]any)) []byte {
	t.Helper();var value map[string]any;if json.Unmarshal(raw,&value)!=nil{t.Fatal("model JSON decode")};fn(value);return labTestJSON(t,value)
}
func labTestClient(t *testing.T,handler http.HandlerFunc,timeout time.Duration) *LabReadbackClient {
	t.Helper();server:=httptest.NewServer(handler);t.Cleanup(server.Close);_,text,err:=net.SplitHostPort(server.Listener.Addr().String());if err!=nil{t.Fatal("model address")};port,err:=strconv.Atoi(text);if err!=nil{t.Fatal("model port")}
	c,err:=NewLabReadbackClient(uint16(port),labTestSecret,timeout);if err!=nil{t.Fatal("model reader")};return c
}
func labTestRead(t *testing.T,first,second map[string][]byte) LabSamples {
	t.Helper();var mu sync.Mutex;requests:=0;order:=[]string{"/version","/configs","/proxies","/rules"}
	c:=labTestClient(t,func(w http.ResponseWriter,r *http.Request){mu.Lock();index:=requests;requests++;mu.Unlock()
		if index>=8||r.URL.Path!=order[index%4]||r.Method!="GET"||r.URL.RawQuery!=""||r.Header.Get("Authorization")!="Bearer "+labTestSecret||r.Header.Get("Accept-Encoding")!="identity"||r.Header.Get("Cookie")!=""{t.Error("fixed request boundary changed");w.WriteHeader(400);return}
		body:=first[r.URL.Path];if index>=4{body=second[r.URL.Path]};w.Header().Set("Content-Type","application/json; charset=utf-8");_,_=w.Write(body)
	},time.Second)
	samples,err:=c.ReadStable(context.Background());if err!=nil{t.Fatal("complete model response rejected")};if requests!=8{t.Fatal("did not make exactly eight sequential requests")};return samples
}
func labTestReport(t *testing.T,samples LabSamples) LabReadbackReport {
	t.Helper();r,err:=CompareLabReadback(samples,labTestExpected(t,false),labTestExpected(t,true));if err!=nil{t.Fatal("complete model comparison rejected")}
	if r.SampleCount!=2||r.RequestsObserved!=8||r.DataplaneProven||r.FullPayloadProven||r.AuthorizationProven||r.Production{t.Fatal("projection gained a success/authority claim")};return r
}
func labTestRejectBody(t *testing.T,path string,body []byte) {
	t.Helper();bodies:=labTestBodies(t,false);bodies[path]=body
	c:=labTestClient(t,func(w http.ResponseWriter,r *http.Request){w.Header().Set("Content-Type","application/json");_,_=w.Write(bodies[r.URL.Path])},time.Second)
	samples,err:=c.ReadStable(context.Background());if err==nil||samples.core!=nil{t.Fatal("invalid response returned usable samples")}
	if !errors.Is(err,ErrLabReadbackShape)&&!errors.Is(err,ErrLabReadbackLimit)&&!errors.Is(err,ErrLabReadbackUnavailable){t.Fatal("error escaped fixed classes")}
}

func TestLabReadbackCompleteSequentialModelObservesOldAndNewProjection(t *testing.T) {
	for _,candidate:=range []bool{false,true}{body:=labTestBodies(t,candidate);r:=labTestReport(t,labTestRead(t,body,body));want:=LabStableOldProjection;if candidate{want=LabStableNewProjection};if r.Conclusion!=want||r.ObservedProjectionSHA256==nil{t.Fatal("wrong projection conclusion")}}
}
func TestLabReadbackEqualExpectationsAreAmbiguousNotFullPayloadProof(t *testing.T) {
	body:=labTestBodies(t,false);samples:=labTestRead(t,body,body);old:=labTestExpected(t,false);r,err:=CompareLabReadback(samples,old,old)
	if err!=nil||r.Conclusion!=LabProjectionAmbiguous||r.FullPayloadProven||r.AuthorizationProven{t.Fatal("equal visible projections pretended to identify full config")}
}
func TestLabReadbackTwoRoundsChangingProjectionOrRuntimeUUIDAreUnstable(t *testing.T) {
	old,newer:=labTestBodies(t,false),labTestBodies(t,true);r:=labTestReport(t,labTestRead(t,old,newer));if r.Conclusion!=LabProjectionUnstable||r.ObservedProjectionSHA256!=nil{t.Fatal("changed rounds claimed stable")}
	newer=labTestBodies(t,false);newer["/proxies"]=labTestMutate(t,newer["/proxies"],func(m map[string]any){m["proxies"].(map[string]any)["http-a"].(map[string]any)["id"]="22222222-2222-4222-8222-222222222222"})
	r=labTestReport(t,labTestRead(t,old,newer));if r.Conclusion!=LabProjectionUnstable||r.ObservedProjectionSHA256!=nil{t.Fatal("object recreation witness ignored")}
}
func TestLabReadbackTelemetryChangesAreValidatedThenExcludedFromProjection(t *testing.T) {
	old,newer:=labTestBodies(t,false),labTestBodies(t,false)
	newer["/proxies"]=labTestMutate(t,newer["/proxies"],func(m map[string]any){p:=m["proxies"].(map[string]any)["http-a"].(map[string]any);p["alive"]=false;p["history"]=[]any{map[string]any{"time":"2026-10-25T01:00:00Z","delay":42}};p["extra"]=map[string]any{"https://example.com/check":map[string]any{"alive":true,"history":nil}}})
	newer["/rules"]=labTestMutate(t,newer["/rules"],func(m map[string]any){e:=m["rules"].([]any)[0].(map[string]any)["extra"].(map[string]any);e["hitCount"]=uint64(18446744073709551615);e["hitAt"]="2026-10-25T01:00:00.123456789Z"})
	r:=labTestReport(t,labTestRead(t,old,newer));if r.Conclusion!=LabStableOldProjection{t.Fatal("dynamic health counters became config identity")}
}
func TestLabReadbackEveryGeneralFlagPortAndNestedDefaultParticipatesInComparison(t *testing.T) {
	for _,edit:=range []func(map[string]any){
		func(m map[string]any){m["allow-lan"]=true},func(m map[string]any){m["mixed-port"]=18081},func(m map[string]any){m["port"]=18082},
		func(m map[string]any){m["ipv6"]=true},func(m map[string]any){m["routing-mark"]=7},func(m map[string]any){m["mode"]="global"},
		func(m map[string]any){m["tun"].(map[string]any)["stack"]="Mixed"},func(m map[string]any){m["tuic-server"].(map[string]any)["enable"]=true},
	}{b:=labTestBodies(t,false);b["/configs"]=labTestMutate(t,b["/configs"],edit);if r:=labTestReport(t,labTestRead(t,b,b));r.Conclusion!=LabProjectionDrift{t.Fatal("general drift ignored")}}
}
func TestLabReadbackGeneralMissingNullCaseAliasAndExtraFieldsReject(t *testing.T) {
	for _,bad:=range []string{
		strings.Replace(labTestGeneral,`"mode":"rule",`,"",1),strings.Replace(labTestGeneral,`"ipv6":false`,`"ipv6":null`,1),
		strings.Replace(labTestGeneral,`"mode":"rule"`,`"Mode":"rule"`,1),strings.Replace(labTestGeneral,`"mode":"rule"`,`"mode":"rule","Mode":"rule"`,1),
		strings.Replace(labTestGeneral,`"mode":"rule"`,`"mode":"rule","private-field":"raw-sensitive"`,1),strings.Replace(labTestGeneral,`"tun":{`,`"tun":null,"discarded":{`,1),
	}{labTestRejectBody(t,"/configs",[]byte(bad))}
}
func TestLabReadbackGeneralNumbersCannotBeFloatsBooleansStringsOrOverflows(t *testing.T) {
	for _,number:=range []string{"18080.0","1.808e4","true",`"18080"`,"18446744073709551616","-1"}{labTestRejectBody(t,"/configs",[]byte(strings.Replace(labTestGeneral,`"mixed-port":18080`,`"mixed-port":`+number,1)))}
}
func TestLabReadbackGeneralSensitiveInboundAndUnsupportedEnumsReject(t *testing.T) {
	for _,edit:=range []func(map[string]any){func(m map[string]any){m["tuic-server"].(map[string]any)["private-key"]="PRIVATE KEY synthetic"},func(m map[string]any){m["ss-config"]="private-password"},func(m map[string]any){m["mode"]="unknown"},func(m map[string]any){m["tun"].(map[string]any)["stack"]="unknown"}}{
		labTestRejectBody(t,"/configs",labTestMutate(t,[]byte(labTestGeneral),edit))
	}
}
func TestLabReadbackVersionRequiresActualTwoFieldsAndPinnedVersion(t *testing.T) {
	for _,bad:=range []string{`{"version":"v1.19.32"}`,`{"meta":null,"version":"v1.19.32"}`,`{"meta":true,"version":"v1.19.31"}`,`{"meta":true,"version":"v1.19.32","premium":false}`,`{"Meta":true,"version":"v1.19.32"}`}{labTestRejectBody(t,"/version",[]byte(bad))}
}
func TestLabReadbackCompleteProxySetIncludesBuiltinsAndGlobal(t *testing.T) {
	for _,name:=range []string{"PASS-RULE","REJECT-DROP"}{b:=labTestBodies(t,false);b["/proxies"]=labTestMutate(t,b["/proxies"],func(m map[string]any){delete(m["proxies"].(map[string]any),name)});if r:=labTestReport(t,labTestRead(t,b,b));r.Conclusion!=LabProjectionDrift{t.Fatal("missing builtin ignored")}}
	b:=labTestBodies(t,false);b["/proxies"]=labTestMutate(t,b["/proxies"],func(m map[string]any){m["proxies"].(map[string]any)["unused-extra"]=labTestProxy("unused-extra","Http",false)});if r:=labTestReport(t,labTestRead(t,b,b));r.Conclusion!=LabProjectionDrift{t.Fatal("extra unused node ignored")}
}
func TestLabReadbackSelectorMembershipOrderCurrentAndMetadataAreCompared(t *testing.T) {
	for _,edit:=range []func(map[string]any){func(p map[string]any){p["all"]=[]string{"DIRECT","http-a"}},func(p map[string]any){p["now"]="DIRECT";p["udp"]=true},func(p map[string]any){p["hidden"]=true},func(p map[string]any){p["emptyFallback"]="DIRECT"}}{
		b:=labTestBodies(t,false);b["/proxies"]=labTestMutate(t,b["/proxies"],func(m map[string]any){edit(m["proxies"].(map[string]any)["cw.business.chat"].(map[string]any))});if r:=labTestReport(t,labTestRead(t,b,b));r.Conclusion!=LabProjectionDrift{t.Fatal("selector detail ignored")}
	}
}
func TestLabReadbackGlobalMembershipOrderIsNotSortedAway(t *testing.T) {
	b:=labTestBodies(t,false);b["/proxies"]=labTestMutate(t,b["/proxies"],func(m map[string]any){m["proxies"].(map[string]any)["GLOBAL"].(map[string]any)["all"]=[]string{"REJECT","DIRECT","http-a","cw.business.chat",labReadbackDefault}})
	if r:=labTestReport(t,labTestRead(t,b,b));r.Conclusion!=LabProjectionDrift{t.Fatal("GLOBAL order ignored")}
}
func TestLabReadbackProxyRequiredPresenceExactCaseAndUnknownPrivateFieldsReject(t *testing.T) {
	for _,edit:=range []func(map[string]any){func(p map[string]any){delete(p,"type")},func(p map[string]any){p["type"]=""},func(p map[string]any){p["type"]="Socks5"},func(p map[string]any){p["udp"]=nil},func(p map[string]any){p["Type"]=p["type"];delete(p,"type")},func(p map[string]any){p["password"]="raw-private"},func(p map[string]any){p["name"]="other"},func(p map[string]any){p["id"]=nil}}{
		b:=labTestBodies(t,false);labTestRejectBody(t,"/proxies",labTestMutate(t,b["/proxies"],func(m map[string]any){edit(m["proxies"].(map[string]any)["http-a"].(map[string]any))}))
	}
}
func TestLabReadbackSelectorEmptyDuplicateUnknownAndUnselectedNowReject(t *testing.T) {
	for _,edit:=range []func(map[string]any){func(p map[string]any){p["all"]=nil},func(p map[string]any){p["all"]=[]string{}},func(p map[string]any){p["all"]=[]string{"http-a","http-a"}},func(p map[string]any){p["all"]=[]string{"missing"};p["now"]="missing"},func(p map[string]any){p["now"]="not-a-member"},func(p map[string]any){p["id"]="unexpected"}}{
		b:=labTestBodies(t,false);labTestRejectBody(t,"/proxies",labTestMutate(t,b["/proxies"],func(m map[string]any){edit(m["proxies"].(map[string]any)["cw.business.chat"].(map[string]any))}))
	}
}
func TestLabReadbackTelemetryCannotHideArbitraryCredentialsOrInvalidTypes(t *testing.T) {
	for _,edit:=range []func(map[string]any){func(p map[string]any){p["alive"]="true"},func(p map[string]any){p["history"]=nil},func(p map[string]any){p["history"]=[]any{map[string]any{"time":"not-time","delay":3}}},func(p map[string]any){p["extra"]=map[string]any{"https://example.com/?token=private":map[string]any{"alive":true,"history":nil}}},func(p map[string]any){p["extra"]=map[string]any{"https://example.com/check":map[string]any{"alive":true,"history":nil,"password":"private"}}}}{
		b:=labTestBodies(t,false);labTestRejectBody(t,"/proxies",labTestMutate(t,b["/proxies"],func(m map[string]any){edit(m["proxies"].(map[string]any)["http-a"].(map[string]any))}))
	}
}
func TestLabReadbackCompleteOrderedRulesAndDisabledStateAreCompared(t *testing.T) {
	for _,edit:=range []func([]any){func(a []any){a[0].(map[string]any)["proxy"]=labReadbackDefault},func(a []any){a[0].(map[string]any)["extra"].(map[string]any)["disabled"]=true},func(a []any){a[0],a[1]=a[1],a[0];a[0].(map[string]any)["index"]=0;a[1].(map[string]any)["index"]=1}}{
		b:=labTestBodies(t,false);b["/rules"]=labTestMutate(t,b["/rules"],func(m map[string]any){edit(m["rules"].([]any))});if r:=labTestReport(t,labTestRead(t,b,b));r.Conclusion!=LabProjectionDrift{t.Fatal("rule order/target/disabled ignored")}
	}
}
func TestLabReadbackRulesMissingExtraBadIndexAndCounterTypesReject(t *testing.T) {
	for _,edit:=range []func(map[string]any){func(r map[string]any){delete(r,"extra")},func(r map[string]any){r["index"]=1},func(r map[string]any){r["payload"]=nil},func(r map[string]any){r["size"]=0},func(r map[string]any){r["extra"].(map[string]any)["hitCount"]=true},func(r map[string]any){r["extra"].(map[string]any)["missAt"]="raw-private"},func(r map[string]any){r["raw"]="credential"},func(r map[string]any){r["proxy"]="missing"}}{
		b:=labTestBodies(t,false);labTestRejectBody(t,"/rules",labTestMutate(t,b["/rules"],func(m map[string]any){edit(m["rules"].([]any)[0].(map[string]any))}))
	}
}
func TestLabReadbackJSONDuplicateEscapedAliasInvalidUTF8DepthAndTrailingValuesReject(t *testing.T) {
	for _,raw:=range [][]byte{[]byte(`{"meta":true,"meta":true,"version":"v1.19.32"}`),[]byte(`{"meta":true,"m\u0065ta":true,"version":"v1.19.32"}`),[]byte(`{"meta":true,"version":"v1.19.32"} {}`),{0xff},[]byte(strings.Repeat("[",26)+"0"+strings.Repeat("]",26))}{labTestRejectBody(t,"/version",raw)}
}
func TestLabReadbackResponseAndStructuredCountsAreBounded(t *testing.T) {
	labTestRejectBody(t,"/version",bytes.Repeat([]byte(" "),labReadbackBodyLimit+1))
	if _,_,err:=labReadProxies(map[string]any{"proxies":map[string]any{}});err!=nil{t.Fatal("empty observed set should remain drift, not invented expected entries")}
	tooMany:=map[string]any{};for i:=0;i<labReadbackProxyLimit+1;i++{tooMany[fmt.Sprintf("p%d",i)]=map[string]any{}}
	if _,_,err:=labReadProxies(map[string]any{"proxies":tooMany});!errors.Is(err,ErrLabReadbackLimit){t.Fatal("proxy count limit missing")}
	if _,err:=labReadRules(map[string]any{"rules":make([]any,labReadbackRuleLimit+1)});!errors.Is(err,ErrLabReadbackLimit){t.Fatal("rule count limit missing")}
}
func TestLabReadbackConstructorCannotSelectRemoteTransportOrUnboundedBudget(t *testing.T) {
	for _,port:=range []uint16{0,80,1023}{if c,err:=NewLabReadbackClient(port,labTestSecret,time.Second);c!=nil||err==nil{t.Fatal("unsafe port accepted")}}
	for _,secret:=range []string{"",strings.Repeat("a",31),strings.Repeat("a",129),strings.Repeat("a",32)+"\n",strings.Repeat("a",32)+" ",strings.Repeat("a",32)+"中"}{if c,err:=NewLabReadbackClient(19090,secret,time.Second);c!=nil||err==nil{t.Fatal("unsafe credential accepted")}}
	if c,err:=NewLabReadbackClient(19090,labTestSecret,31*time.Second);c!=nil||err==nil{t.Fatal("unbounded total budget accepted")}
	c,err:=NewLabReadbackClient(19090,labTestSecret,0);if err!=nil||c.core.timeout!=5*time.Second||c.core.endpoint!="http://127.0.0.1:19090"{t.Fatal("fixed constructor changed")}
	transport:=c.core.client.Transport.(*http.Transport);if transport.Proxy!=nil||!transport.DisableCompression||!transport.DisableKeepAlives||transport.ForceAttemptHTTP2||transport.MaxResponseHeaderBytes!=16<<10||c.core.client.Jar!=nil{t.Fatal("implicit transport capability introduced")}
}
func TestLabReadbackRedirectDoesNotFollowOrExposeBearer(t *testing.T) {
	hits:=0;target:=httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter,*http.Request){hits++}));defer target.Close()
	c:=labTestClient(t,func(w http.ResponseWriter,r *http.Request){http.Redirect(w,r,target.URL,302)},time.Second)
	if samples,err:=c.ReadStable(context.Background());err==nil||samples.core!=nil||hits!=0{t.Fatal("redirect followed or fake samples returned")}
}
func TestLabReadbackHTTPFailureMediaEncodingAndPrivateBodiesNeverProduceSamples(t *testing.T) {
	for _,kind:=range []string{"status","cookie","media","gzip","charset"}{
		c:=labTestClient(t,func(w http.ResponseWriter,r *http.Request){w.Header().Set("Content-Type","application/json");switch kind{case "status":w.WriteHeader(403);case "cookie":w.Header().Set("Set-Cookie","private=value");case "media":w.Header().Set("Content-Type","text/html");case "gzip":w.Header().Set("Content-Encoding","gzip");case "charset":w.Header().Set("Content-Type","application/json; charset=latin1")};_,_=w.Write([]byte("raw-sensitive-response"))},time.Second)
		samples,err:=c.ReadStable(context.Background());if err==nil||samples.core!=nil||strings.Contains(err.Error(),"raw-sensitive")||strings.Contains(err.Error(),labTestSecret){t.Fatal("private response escaped or gained samples")}
	}
}
func TestLabReadbackTotalDeadlineAndCallerCancellationDoNotReturnPartialSamples(t *testing.T) {
	var mu sync.Mutex;requests:=0;b:=labTestBodies(t,false)
	c:=labTestClient(t,func(w http.ResponseWriter,r *http.Request){mu.Lock();requests++;mu.Unlock();select{case <-time.After(25*time.Millisecond):w.Header().Set("Content-Type","application/json");_,_=w.Write(b[r.URL.Path]);case <-r.Context().Done():}},65*time.Millisecond)
	if samples,err:=c.ReadStable(context.Background());err==nil||samples.core!=nil{t.Fatal("partial deadline result accepted")};mu.Lock();count:=requests;mu.Unlock();if count>=8{t.Fatal("timeout budget reset for each request")}
	ctx,cancel:=context.WithCancelCause(context.Background());cancel(errors.New("private cancellation reason"));if samples,err:=c.ReadStable(ctx);err==nil||samples.core!=nil||strings.Contains(err.Error(),"private"){t.Fatal("caller reason escaped")}
}
func TestLabReadbackInputExpectationClosureOrderCyclesAndLimitsReject(t *testing.T) {
	for _,edit:=range []func(*LabExpectedSpec){func(s *LabExpectedSpec){s.HTTPNames=nil},func(s *LabExpectedSpec){s.HTTPNames=[]string{"http-a","http-a"}},func(s *LabExpectedSpec){s.HTTPNames=[]string{"DIRECT"}},func(s *LabExpectedSpec){s.Selectors[0].Members=[]string{}},func(s *LabExpectedSpec){s.Selectors[0].Members=[]string{"missing"}},func(s *LabExpectedSpec){s.Selectors[0].Members=[]string{"cw.business.chat"};s.Selectors[1].Members=[]string{labReadbackDefault}},func(s *LabExpectedSpec){s.Rules[0].Type="GeoIP"},func(s *LabExpectedSpec){s.Rules[0].Payload="EXAMPLE.COM"},func(s *LabExpectedSpec){s.Rules[1].Proxy="DIRECT"}}{
		s:=labTestSpec(false);edit(&s);if value,err:=NewLabExpectation(s);err==nil||value.core!=nil{t.Fatal("invalid expected declaration accepted")}
	}
}
func TestLabReadbackExpectationCopiesAndReportHashPointersAreOwned(t *testing.T) {
	spec:=labTestSpec(false);expected,err:=NewLabExpectation(spec);if err!=nil{t.Fatal(err)};before:=expected.core.digest;spec.HTTPNames[0]="mutated";spec.Selectors[0].Members[0]="mutated";spec.Rules[0].Payload="mutated.invalid"
	if after,_:=labProjectionDigest(expected.core.projection);after!=before{t.Fatal("caller mutated retained expectation")}
	if hash,err:=expected.ProjectionSHA256();err!=nil||hash!=before{t.Fatal("safe metadata digest unstable after caller mutation")}
	body:=labTestBodies(t,false);samples:=labTestRead(t,body,body);r,err:=CompareLabReadback(samples,expected,labTestExpected(t,true));if err!=nil{t.Fatal(err)};*r.ObservedProjectionSHA256="mutated"
	if r2,err:=CompareLabReadback(samples,expected,labTestExpected(t,true));err!=nil||r2.ObservedProjectionSHA256==nil||*r2.ObservedProjectionSHA256!=before{t.Fatal("report pointer mutated private samples")}
}
type labNilContext struct{}
func (*labNilContext) Deadline()(time.Time,bool){panic("nil context accessed")}
func (*labNilContext) Done()<-chan struct{}{panic("nil context accessed")}
func (*labNilContext) Err()error{panic("nil context accessed")}
func (*labNilContext) Value(any)any{panic("nil context accessed")}
func TestLabReadbackNilZeroTypedNilAndImportedWrappersFailClosed(t *testing.T) {
	var ctx *labNilContext
	for _,c:=range []*LabReadbackClient{nil,{}}{if samples,err:=c.ReadStable(ctx);err==nil||samples.core!=nil{t.Fatal("nil reader accepted")}}
	if _,err:=CompareLabReadback(LabSamples{},LabExpectation{},LabExpectation{});err==nil{t.Fatal("zero declaration accepted")}
	var nilExpected *LabExpectation;for _,e:=range []*LabExpectation{nilExpected,{}, {core:&labExpectedCore{digest:"forged"}}}{if hash,err:=e.ProjectionSHA256();err==nil||hash!=""{t.Fatal("zero or forged digest accepted")}}
	value:=labTestExpected(t,false);if json.Unmarshal([]byte(`{"core":{}}`),&value)==nil||value.core!=nil{t.Fatal("JSON retained/imported expected authority")}
	c,_:=NewLabReadbackClient(19090,labTestSecret,time.Second);if samples,err:=c.ReadStable(ctx);err==nil||samples.core!=nil{t.Fatal("typed nil context accepted")}
}
func TestLabReadbackAllWrappersPreventPointerValueAndSpecialVerbPrivateReflection(t *testing.T) {
	c,_:=NewLabReadbackClient(19090,labTestSecret,time.Second);expect:=labTestExpected(t,false);b:=labTestBodies(t,false);samples:=labTestRead(t,b,b)
	for _,v:=range []any{c,*c,expect,&expect,samples,&samples,LabReadbackClient{},LabExpectation{},LabSamples{}}{
		for _,verb:=range []string{"%v","%+v","%#v","%x","%s"}{if fmt.Sprintf(verb,v)!=labReadbackLabel{t.Fatal("ordinary private formatter changed")}}
		for _,verb:=range []string{"%p","%d","%T","%w"}{s:=fmt.Sprintf(verb,v);for _,needle:=range []string{labTestSecret,hex.EncodeToString([]byte(labTestSecret)),base64.StdEncoding.EncodeToString([]byte(labTestSecret)),"http://127.0.0.1:19090","http-a","cw.business.chat",labTestGeneral}{if strings.Contains(s,needle){t.Fatal("fmt fallback exposed private core")}}}
		for _,typ:=range []reflect.Type{reflect.TypeOf(LabReadbackClient{}),reflect.TypeOf(LabExpectation{}),reflect.TypeOf(LabSamples{})}{if typ.NumField()!=1||typ.Field(0).Type.Kind()!=reflect.Pointer{t.Fatal("wrapper gained inline private fields")}}
		raw,err:=json.Marshal(v);if err!=nil||bytes.Contains(raw,[]byte(labTestSecret))||bytes.Contains(raw,[]byte("http-a")){t.Fatal("private JSON escaped")}
	}
	var nilClient *LabReadbackClient;var nilExpected *LabExpectation;var nilSamples *LabSamples
	for _,v:=range []any{nilClient,nilExpected,nilSamples}{if fmt.Sprintf("%#v",v)!="<nil>"{t.Fatal("nil formatter")};raw,err:=json.Marshal(v);if err!=nil||string(raw)!="null"{t.Fatal("nil JSON")}}
}
func TestLabReadbackOnlyTenSafeReportFieldsAndPrivateTamperingCannotFakeStable(t *testing.T) {
	body:=labTestBodies(t,false);samples:=labTestRead(t,body,body);r:=labTestReport(t,samples);raw:=labTestJSON(t,r);var fields map[string]any;if json.Unmarshal(raw,&fields)!=nil||len(fields)!=10{t.Fatal("report wire expanded")}
	for _,key:=range []string{"conclusion","sampleCount","requestsObserved","previousProjectionSHA256","candidateProjectionSHA256","observedProjectionSHA256","dataplaneProven","fullPayloadProven","authorizationProven","production"}{if _,ok:=fields[key];!ok{t.Fatal("safe report key missing")}}
	samples.core.samples[1].digest=strings.Repeat("0",64);if _,err:=CompareLabReadback(samples,labTestExpected(t,false),labTestExpected(t,true));err==nil{t.Fatal("tampered model digest accepted")}
}
