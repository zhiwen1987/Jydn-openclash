package mihomo

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

// All responses, PIDs and credentials in these tests are MODEL fixtures.
// A private same-package RoundTripper is not a product injection interface or
// evidence of an actual controller/kernel run. No real network is required.
type labEvidenceTestRT func(*http.Request)(*http.Response,error)
func (f labEvidenceTestRT) RoundTrip(r *http.Request)(*http.Response,error){return f(r)}
type labEvidenceTestBody struct {
	raw []byte
	readError error
	closeError error
	onRead func()
	onClose func()
	reads int
	closes int
}
func (b *labEvidenceTestBody) Read(p []byte)(int,error){
	b.reads++;if b.onRead!=nil {f:=b.onRead;b.onRead=nil;f()}
	if len(b.raw)==0 {if b.readError!=nil{return 0,b.readError};return 0,io.EOF}
	n:=copy(p,b.raw);b.raw=b.raw[n:]
	if len(b.raw)==0 {if b.readError!=nil{return n,b.readError};return n,io.EOF}
	return n,nil
}
func (b *labEvidenceTestBody) Close()error{b.closes++;if b.onClose!=nil {b.onClose()};return b.closeError}

func labEvidenceModel(t *testing.T,change func(int,*http.Request,*http.Response)error)(*LabReadbackClient,*int,*int){
	t.Helper();bodies:=labTestBodies(t,false);requests,closes:=0,0
	c,err:=NewLabReadbackClient(18081,labTestSecret,30*time.Second);if err!=nil{t.Fatal("MODEL constructor")}
	c.core.client.Transport=labEvidenceTestRT(func(req *http.Request)(*http.Response,error){
		requests++;order:=[]string{"/version","/configs","/proxies","/rules"}
		if requests>16||req.URL.Path!=order[(requests-1)%4]||req.URL.Host!="127.0.0.1:18081"||req.Method!="GET"||req.Body!=nil||req.URL.RawQuery!=""||req.Header.Get("Authorization")!="Bearer "+labTestSecret {t.Error("MODEL fixed request boundary")}
		raw:=append([]byte(nil),bodies[req.URL.Path]...)
		body:=&labEvidenceTestBody{raw:raw,onClose:func(){closes++}}
		response:=&http.Response{StatusCode:200,Header:http.Header{"Content-Type":[]string{"application/json"}},ContentLength:-1,Body:body,Request:req}
		if change!=nil {if err:=change(requests,req,response);err!=nil{return nil,err}}
		return response,nil
	})
	return c,&requests,&closes
}
func labEvidenceWire(t *testing.T,e *LabReadbackEvidence) labEvidenceTranscript {
	t.Helper();raw,err:=e.PrivateTranscript();if err!=nil{t.Fatal("MODEL transcript unavailable")}
	var w labEvidenceTranscript;if json.Unmarshal(raw,&w)!=nil{t.Fatal("MODEL transcript malformed")};return w
}
func labEvidenceCapture(t *testing.T,c *LabReadbackClient)(LabSamples,LabReadbackEvidence){
	t.Helper();samples,e,err:=c.ReadStableCaptured(context.Background());if err!=nil{t.Fatal("MODEL capture rejected")}
	t.Cleanup(func(){_ = e.Release()});return samples,e
}

func TestLabEvidenceCapturedBytesAreTheSingleDecoderInput(t *testing.T){
	version:=[]byte(" \n{ \"meta\": true, \"version\": \"v1.19.32\" }\t")
	c,n,closed:=labEvidenceModel(t,func(_ int,r *http.Request,s *http.Response)error{if r.URL.Path=="/version"{s.Body.(*labEvidenceTestBody).raw=append([]byte(nil),version...)};return nil})
	s,e:=labEvidenceCapture(t,c);if s.core==nil||*n!=8||*closed!=8{t.Fatal("MODEL capture added/missed requests or close")}
	for _,i:=range []uint8{1,5}{raw,err:=e.PrivateBody(i);if err!=nil||!bytes.Equal(raw,version){t.Fatal("original bytes normalized or replaced")}}
	w:=labEvidenceWire(t,&e);if w.Outcome!="COMPLETE"||w.SlotsEntered!=8||w.CompletedBodies!=8||w.DoInvocations!=8{t.Fatal("capture not complete")}
	for _,r:=range w.Records{if r.ParseState!="SHAPE_ACCEPTED"||r.TerminalClass!="NONE"||r.CloseErrorClass==nil||*r.CloseErrorClass!="NONE"{t.Fatal("slot falsely accepted")}}
}
func TestLabEvidenceTranscriptHasExactOrderedClosedFields(t *testing.T){
	c,_,_:=labEvidenceModel(t,nil);_,e:=labEvidenceCapture(t,c);raw,_:=e.PrivateTranscript();w:=labEvidenceWire(t,&e)
	if len(w.ExpectedSchedule)!=8||len(w.Records)!=8||raw[len(raw)-1]!='\n'{t.Fatal("schedule/framing")}
	for i,s:=range w.ExpectedSchedule{if s.Ordinal!=i+1||s.Round!=i/4+1||s.EndpointKind!=[]string{"VERSION","CONFIGS","PROXIES","RULES"}[i%4]{t.Fatal("schedule differs from source")}}
	var object map[string]json.RawMessage;if json.Unmarshal(raw,&object)!=nil||len(object)!=14{t.Fatal("top exact keys")}
	keys:=[]string{"schema","scope","expectedSchedule","records","slotsEntered","doInvocations","responsesObserved","readAttempts","completedBodies","retainedBytes","outcome","failureClass","limitReached","contextState"}
	decoder:=json.NewDecoder(bytes.NewReader(raw));_,_ = decoder.Token()
	for _,key:=range keys{token,err:=decoder.Token();if err!=nil||token!=key{t.Fatal("top key order")};var skipped json.RawMessage;if decoder.Decode(&skipped)!=nil{t.Fatal("top value")}}
	row,_:=json.Marshal(w.Records[0]);var fields map[string]json.RawMessage;_ = json.Unmarshal(row,&fields);if len(fields)!=21{t.Fatal("record exact fields")}
}
func TestLabEvidenceLegacyAPIUsesSharedPathWithoutRetainedArchive(t *testing.T){
	c,n,closed:=labEvidenceModel(t,nil);s,err:=c.ReadStable(context.Background())
	if err!=nil||s.core==nil||*n!=8||*closed!=8||c.core.capture!=nil{t.Fatal("legacy signature or archive behavior changed")}
	_,e:=labEvidenceCapture(t,c);if *n!=16{t.Fatal("legacy performed extra reads")};_ = e.Release()
}
func TestLabEvidenceRetainedGateAndCopiedHandlesReleaseOnce(t *testing.T){
	c,n,_:=labEvidenceModel(t,nil);_,e:=labEvidenceCapture(t,c);copyClient:=*c
	_,empty,err:=copyClient.ReadStableCaptured(context.Background());if !errors.Is(err,ErrLabEvidenceBusy)||empty.core!=nil||*n!=8{t.Fatal("copied client bypassed retained gate")}
	want,_:=e.PrivateBody(1);alias:=e;start:=make(chan struct{});results:=make(chan error,2)
	type getterResult struct{raw []byte;err error};got:=make(chan getterResult,1)
	go func(){<-start;results<-alias.Release()}();go func(){<-start;results<-e.Release()}()
	go func(){<-start;raw,err:=alias.PrivateBody(1);got<-getterResult{raw,err}}();close(start)
	successes:=0;for i:=0;i<2;i++{err:=<-results;if err==nil{successes++}else if !errors.Is(err,ErrLabEvidenceUnavailable){t.Fatal("unexpected release result")}}
	if successes!=1{t.Fatal("copied aliases released gate multiple times")};read:=<-got;if read.err==nil&&!bytes.Equal(read.raw,want){t.Fatal("concurrent getter returned changed bytes")};if read.err!=nil&&!errors.Is(read.err,ErrLabEvidenceUnavailable){t.Fatal("concurrent getter error")}
	if _,err=e.PrivateBody(1);err==nil{t.Fatal("alias revived released body")}
	if e.Release()==nil{t.Fatal("double release")};_,next,err:=c.ReadStableCaptured(context.Background());if err!=nil||*n!=16{t.Fatal("release did not return gate")};_ = next.Release()
}
func TestLabEvidenceConcurrentCaptureCannotIssueAdditionalRequest(t *testing.T){
	entered,release:=make(chan struct{}),make(chan struct{});c,n,_:=labEvidenceModel(t,func(i int,_ *http.Request,s *http.Response)error{if i==1{s.Body.(*labEvidenceTestBody).onRead=func(){close(entered);<-release}};return nil})
	done:=make(chan LabReadbackEvidence,1);go func(){_,e,_:=c.ReadStableCaptured(context.Background());done<-e}()
	<-entered;_,e,err:=c.ReadStableCaptured(context.Background());if !errors.Is(err,ErrLabEvidenceBusy)||e.core!=nil{close(release);t.Fatal("concurrent capture accepted")}
	close(release);captured:=<-done;_ = captured.Release();if *n!=8{t.Fatal("busy call issued a request")}
}
func TestLabEvidencePrivateGettersAndDescriptorAreDetached(t *testing.T){
	c,_,_:=labEvidenceModel(t,nil);_,e:=labEvidenceCapture(t,c)
	body,_:=e.PrivateBody(1);before:=append([]byte(nil),body...);body[0]^=1;again,_:=e.PrivateBody(1);if !bytes.Equal(again,before){t.Fatal("body alias")}
	raw,_:=e.PrivateTranscript();hash:=labDigest(raw);raw[0]^=1;again,_=e.PrivateTranscript();d,err:=e.Descriptor();if err!=nil||labDigest(again)!=hash||d.TranscriptSHA256!=hash||d.TranscriptBytes!=int64(len(again)){t.Fatal("transcript alias")}
	if _,err=e.PrivateBody(0);err==nil{t.Fatal("zero ordinal")};if _,err=e.PrivateBody(9);err==nil{t.Fatal("unentered ordinal")}
}
func TestLabEvidenceZeroTypedNilAndImportedValuesExposeNoPrivateBacking(t *testing.T){
	var nilEvidence *LabReadbackEvidence;for _,e:=range []*LabReadbackEvidence{nilEvidence,{}, {core:&labEvidenceCore{}}}{if _,err:=e.Descriptor();err==nil{t.Fatal("zero descriptor")};if _,err:=e.PrivateTranscript();err==nil{t.Fatal("zero transcript")};if _,err:=e.PrivateBody(1);err==nil{t.Fatal("zero body")}}
	var badContext *labNilContext
	for _,client:=range []*LabReadbackClient{nil,{}}{if samples,e,err:=client.ReadStableCaptured(badContext);err==nil||samples.core!=nil||e.core!=nil{t.Fatal("nil client/context invented capture")}}
	valid,n,_:=labEvidenceModel(t,nil);if _,empty,err:=valid.ReadStableCaptured(badContext);err==nil||empty.core!=nil||*n!=0||valid.core.capture!=nil{t.Fatal("typed nil context entered capture")}
	c,_,_:=labEvidenceModel(t,nil);_,e:=labEvidenceCapture(t,c);alias:=e
	if json.Unmarshal([]byte(`{"forged":true}`),&e)==nil||e.core!=nil{t.Fatal("JSON created evidence")};if _,err:=alias.PrivateBody(1);err==nil{t.Fatal("JSON reject failed to release old core")}
	secret:=labTestSecret;for _,v:=range []any{alias,&alias,LabReadbackEvidence{},nilEvidence}{for _,verb:=range []string{"%v","%+v","%#v","%x","%d","%p"}{text:=fmt.Sprintf(verb,v);if strings.Contains(text,secret)||strings.Contains(text,"raw:")||strings.Contains(text,"bodies:"){t.Fatal("private formatter reflection")}};raw,_:=json.Marshal(v);if bytes.Contains(raw,[]byte(secret)){t.Fatal("JSON leak")}}
}
func TestLabEvidenceReadEntityRetainsDataAlongsideActualError(t *testing.T){
	for _,err:=range []error{errors.New("MODEL IO"),context.Canceled,context.DeadlineExceeded}{b:=&labEvidenceTestBody{raw:[]byte("prefix"),readError:err};raw,eof,got:=labReadEntity(b);if string(raw)!="prefix"||eof||!errors.Is(got,err){t.Fatal("data/error observation lost")}}
	b:=&labEvidenceTestBody{raw:[]byte("done")};raw,eof,err:=labReadEntity(b);if err!=nil||!eof||string(raw)!="done"{t.Fatal("data+EOF not retained")}
}
func TestLabEvidenceNaturalEOFIsNotTheProbeBoundary(t *testing.T){
	for _,natural:=range []bool{false,true}{rawBody:=bytes.Repeat([]byte{' '},labReadbackBodyLimit+1);var reader io.Reader=bytes.NewReader(rawBody);if natural{reader=&labEvidenceTestBody{raw:rawBody}}
		raw,eof,err:=labReadEntity(reader);if err!=nil||len(raw)!=labReadbackBodyLimit+1||eof!=natural||cap(raw)>labReadbackBodyLimit+1{t.Fatal("limit fabricated or erased EOF")}}
}
func TestLabEvidenceHeaderRejectionClosesWithoutDiagnosticBodyRead(t *testing.T){
	for _,kind:=range []string{"status","cookie","type","encoding","advertised"}{var seen *labEvidenceTestBody;c,n,_:=labEvidenceModel(t,func(_ int,_ *http.Request,r *http.Response)error{seen=r.Body.(*labEvidenceTestBody);switch kind{case "status":r.StatusCode=401;case "cookie":r.Header.Add("Set-Cookie","MODEL_PRIVATE_COOKIE");case "type":r.Header.Set("Content-Type","text/plain");case "encoding":r.Header.Set("Content-Encoding","gzip");case "advertised":r.ContentLength=labReadbackBodyLimit+1};return nil})
		_,e,err:=c.ReadStableCaptured(context.Background());if err==nil||*n!=1||seen.reads!=0||seen.closes!=1{t.Fatal("header failure read or skipped close")};w:=labEvidenceWire(t,&e);if w.ReadAttempts!=0||w.Records[0].RetainedBytes!=nil{t.Fatal("invented empty body")};if _,err=e.PrivateBody(1);err==nil{t.Fatal("unread body available")};_ = e.Release()}
}
func TestLabEvidenceObservedEmptyHeaderArraysAndBoundedHeaderCopies(t *testing.T){
	c,_,_:=labEvidenceModel(t,nil);_,e:=labEvidenceCapture(t,c);w:=labEvidenceWire(t,&e);h:=w.Records[0].Headers
	if h==nil||h.ContentEncodingValuesB64==nil||h.TransferEncodingValuesB64==nil||len(h.ContentEncodingValuesB64)!=0{t.Fatal("observed empty arrays became null")};_ = e.Release()
	for _,missing:=range []bool{true,false}{cookie:="MODEL_PRIVATE_COOKIE_VALUE";header:=string([]byte{'x',0xff,'y'});c,_,_=labEvidenceModel(t,func(_ int,_ *http.Request,r *http.Response)error{if missing{r.Header.Del("Content-Type")}else{r.Header.Set("Content-Type",header);r.Header.Set("Set-Cookie",cookie)};return nil})
		_,e,err:=c.ReadStableCaptured(context.Background());if err==nil{t.Fatal("bad header accepted")};w=labEvidenceWire(t,&e);h=w.Records[0].Headers
		if missing{if h.ContentTypeValuesB64==nil||len(h.ContentTypeValuesB64)!=0{t.Fatal("observed absent Content-Type became unknown")}}else{value,decodeErr:=base64.StdEncoding.DecodeString(h.ContentTypeValuesB64[0]);if decodeErr!=nil||string(value)!=header||h.SetCookieCount!=1{t.Fatal("selected bytes normalized")};transcript,_:=e.PrivateTranscript();if bytes.Contains(transcript,[]byte(cookie))||bytes.Contains(transcript,[]byte(base64.StdEncoding.EncodeToString([]byte(cookie)))){t.Fatal("cookie value retained")}};_ = e.Release()}
	c,_,_=labEvidenceModel(t,func(_ int,_ *http.Request,r *http.Response)error{r.Header["Content-Type"]=[]string{strings.Repeat("x",labEvidenceHeaderLimit+1)};return nil});_,e,err:=c.ReadStableCaptured(context.Background());if err==nil{t.Fatal("header overage")};w=labEvidenceWire(t,&e);if w.Records[0].Headers!=nil||w.Records[0].TerminalClass!="LIMIT"||!w.LimitReached{t.Fatal("header overage not recorded")};_ = e.Release()
}
func TestLabEvidenceCloseErrorFailsLegacyAndCapturedWithoutLosingBytes(t *testing.T){
	for _,captured:=range []bool{false,true}{c,_,closed:=labEvidenceModel(t,func(_ int,_ *http.Request,r *http.Response)error{r.Body.(*labEvidenceTestBody).closeError=errors.New("MODEL close");return nil})
		if !captured{samples,err:=c.ReadStable(context.Background());if err==nil||samples.core!=nil||*closed!=1{t.Fatal("legacy ignored Close error")};continue}
		_,e,err:=c.ReadStableCaptured(context.Background());if err==nil||*closed!=1{t.Fatal("capture ignored Close error")};w:=labEvidenceWire(t,&e);if w.CompletedBodies!=1||w.Records[0].TerminalClass!="CLOSE"||*w.Records[0].CloseErrorClass!="IO"{t.Fatal("close error erased actual EOF")};if raw,e2:=e.PrivateBody(1);e2!=nil||len(raw)==0{t.Fatal("closed body discarded")};_ = e.Release()}
}
func TestLabEvidenceReadErrorAndCurrentCancellationRemainIndependent(t *testing.T){
	ctx,cancel:=context.WithCancel(context.Background());defer cancel()
	c,_,_:=labEvidenceModel(t,func(_ int,_ *http.Request,r *http.Response)error{b:=r.Body.(*labEvidenceTestBody);b.raw=[]byte("actual prefix");b.readError=errors.New("MODEL independent IO");b.onRead=cancel;return nil})
	_,e,err:=c.ReadStableCaptured(ctx);if err==nil{t.Fatal("read/cancel accepted")};w:=labEvidenceWire(t,&e);r:=w.Records[0];if r.ReadErrorClass==nil||*r.ReadErrorClass!="IO"||r.ContextState!="CANCELED"||r.TerminalClass!="READ"||w.CompletedBodies!=0{t.Fatal("inferred error causality")};raw,_:=e.PrivateBody(1);if string(raw)!="actual prefix"{t.Fatal("prefix missing")};_ = e.Release()
}
func TestLabEvidenceCancellationAfterEOFDoesNotInventAnUnreadBody(t *testing.T){
	ctx,cancel:=context.WithCancel(context.Background());defer cancel();c,_,closed:=labEvidenceModel(t,func(_ int,_ *http.Request,r *http.Response)error{r.Body.(*labEvidenceTestBody).onRead=cancel;return nil})
	_,e,err:=c.ReadStableCaptured(ctx);if err==nil{t.Fatal("canceled read accepted")};w:=labEvidenceWire(t,&e);if *closed!=1||w.CompletedBodies!=1||w.SlotsEntered!=1||w.Records[0].TerminalClass!="CONTEXT"||*w.Records[0].ReadErrorClass!="NONE"{t.Fatal("actual EOF/cancellation mixed")};_ = e.Release()
}
func TestLabEvidenceJSONAndEndpointShapeFailuresMarkTheActualSlot(t *testing.T){
	for _,kind:=range []string{"json","depth","version","general"}{c,n,_:=labEvidenceModel(t,func(_ int,q *http.Request,r *http.Response)error{b:=r.Body.(*labEvidenceTestBody);if kind=="json"&&q.URL.Path=="/version"{b.raw=[]byte("{")};if kind=="depth"&&q.URL.Path=="/version"{b.raw=[]byte(strings.Repeat("[",26)+"0"+strings.Repeat("]",26))};if kind=="version"&&q.URL.Path=="/version"{b.raw=[]byte(`{"meta":true,"version":"wrong"}`)};if kind=="general"&&q.URL.Path=="/configs"{b.raw=[]byte(`{}`)};return nil})
		_,e,err:=c.ReadStableCaptured(context.Background());if err==nil{t.Fatal("shape accepted")};w:=labEvidenceWire(t,&e);r:=w.Records[len(w.Records)-1];want:="SHAPE_REJECTED";if kind=="json"||kind=="depth"{want="JSON_REJECTED"};if r.ParseState!=want||*n!=len(w.Records)||len(w.Records)>2{t.Fatal("wrong slot or padding")};if kind=="depth"&&(!w.LimitReached||r.TerminalClass!="LIMIT"||w.CompletedBodies!=1){t.Fatal("depth limit erased actual complete body")};_ = e.Release()}
}
func TestLabEvidenceLateRuleReferenceFailureIsNotShapeAccepted(t *testing.T){
	c,n,_:=labEvidenceModel(t,func(_ int,q *http.Request,r *http.Response)error{if q.URL.Path=="/rules"{b:=r.Body.(*labEvidenceTestBody);b.raw=bytes.ReplaceAll(b.raw,[]byte(`"cw.business.chat"`),[]byte(`"missing-model-proxy"`))};return nil})
	_,e,err:=c.ReadStableCaptured(context.Background());if err==nil||*n!=4{t.Fatal("unknown reference accepted")};w:=labEvidenceWire(t,&e);if w.Records[3].ParseState!="SHAPE_REJECTED"||w.Records[3].TerminalClass!="SHAPE"{t.Fatal("rule reference failure lost")};_ = e.Release()
}
func TestLabEvidenceDoFailurePreservesNoResponseAndNoPaddedSlots(t *testing.T){
	c,n,_:=labEvidenceModel(t,func(int,*http.Request,*http.Response)error{return errors.New("MODEL network private text")})
	_,e,err:=c.ReadStableCaptured(context.Background());if err==nil||*n!=1{t.Fatal("network failure accepted")};w:=labEvidenceWire(t,&e);r:=w.Records[0];if w.SlotsEntered!=1||w.DoInvocations!=1||w.ResponsesObserved!=0||r.StatusCode!=nil||r.Headers!=nil||r.RetainedBytes!=nil||r.CloseAttempted||r.TerminalClass!="NETWORK"{t.Fatal("unobserved fields fabricated")};_ = e.Release()
}
func TestLabEvidenceOversizeRetainsTheProbeAndRejectsSamples(t *testing.T){
	c,_,_:=labEvidenceModel(t,func(_ int,_ *http.Request,r *http.Response)error{r.Body.(*labEvidenceTestBody).raw=bytes.Repeat([]byte{'x'},labReadbackBodyLimit+1);return nil})
	s,e,err:=c.ReadStableCaptured(context.Background());if err==nil||s.core!=nil{t.Fatal("oversize samples")};w:=labEvidenceWire(t,&e);raw,_:=e.PrivateBody(1);if len(raw)!=labReadbackBodyLimit+1||!w.LimitReached||w.CompletedBodies!=0||w.Records[0].TerminalClass!="LIMIT"||!*w.Records[0].NaturalEOF{t.Fatal("probe/EOF facts lost")};_ = e.Release()
}
func TestLabEvidenceCapturedScheduleUsesOneFiveSecondContext(t *testing.T){
	var deadline time.Time;c,n,_:=labEvidenceModel(t,func(_ int,r *http.Request,_ *http.Response)error{d,ok:=r.Context().Deadline();if !ok||time.Until(d)>5*time.Second{t.Error("capture budget not capped")};if deadline.IsZero(){deadline=d}else if !deadline.Equal(d){t.Error("deadline reset per GET")};return nil})
	_,e:=labEvidenceCapture(t,c);if *n!=8{t.Fatal("request count")};_ = e.Release()
}
func TestLabEvidenceFinalContextExpiryDoesNotInventNinthRecord(t *testing.T){
	c,n,_:=labEvidenceModel(t,nil);ctx,cancel:=context.WithCancel(context.Background())
	core:=&labEvidenceCore{wire:labEvidenceTranscript{Schema:labEvidenceSchema,Scope:labEvidenceScope,ExpectedSchedule:labEvidenceSchedule(),Records:make([]labEvidenceRecord,0,8)},bodies:make([][]byte,0,8)}
	if _,err:=c.readStable(ctx,core);err!=nil{t.Fatal("MODEL completed read")};cancel();if core.finish(ctx,nil)==nil{t.Fatal("expired overall context accepted")}
	e:=LabReadbackEvidence{core:core};w:=labEvidenceWire(t,&e);if *n!=8||len(w.Records)!=8||w.CompletedBodies!=8||w.FailureClass==nil||*w.FailureClass!="CONTEXT"{t.Fatal("expiry padded or erased completed records")};for _,r:=range w.Records{if r.TerminalClass!="NONE"{t.Fatal("retroactive slot failure")}};_ = e.Release()
}
func TestLabEvidenceActualEmptyReadDiffersFromUnavailableBody(t *testing.T){
	c,_,_:=labEvidenceModel(t,func(_ int,_ *http.Request,r *http.Response)error{r.Body.(*labEvidenceTestBody).raw=[]byte{};return nil})
	_,e,err:=c.ReadStableCaptured(context.Background());if err==nil{t.Fatal("empty JSON accepted")};raw,bodyErr:=e.PrivateBody(1);w:=labEvidenceWire(t,&e);if bodyErr!=nil||raw==nil||len(raw)!=0||w.CompletedBodies!=1||w.Records[0].RetainedBytes==nil||*w.Records[0].RetainedBytes!=0{t.Fatal("actual empty read unavailable/faked")};_ = e.Release()
}
func TestLabEvidenceDefaultFormattingAndDescriptorNeverExportPrivateObjects(t *testing.T){
	private:=[]byte("MODEL_CAPTURE_PRIVATE_SENTINEL")
	c,_,_:=labEvidenceModel(t,func(_ int,_ *http.Request,r *http.Response)error{r.Body.(*labEvidenceTestBody).raw=append([]byte(nil),private...);return nil})
	_,e,_:=c.ReadStableCaptured(context.Background());defer e.Release()
	for _,value:=range []any{e,&e}{for _,verb:=range []string{"%v","%+v","%#v","%x","%d","%p"}{text:=fmt.Sprintf(verb,value);if strings.Contains(text,string(private))||strings.Contains(text,base64.StdEncoding.EncodeToString(private))||strings.Contains(text,"records:"){t.Fatal("private reflection")}};raw,_:=json.Marshal(value);if bytes.Contains(raw,private){t.Fatal("default JSON leaked")}}
	d,err:=e.Descriptor();if err!=nil{t.Fatal("safe failure descriptor missing")};raw,_:=json.Marshal(d);var fields map[string]any;_ = json.Unmarshal(raw,&fields);if len(fields)!=14||bytes.Contains(raw,private){t.Fatal("descriptor contains private data")};if d.FailureClass==nil{t.Fatal("failure descriptor")};*d.FailureClass="MODEL_MUTATION";again,_:=e.Descriptor();if reflect.DeepEqual(d.FailureClass,again.FailureClass){t.Fatal("descriptor pointer alias")}
}
