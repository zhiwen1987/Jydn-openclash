package mihomodeploy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func expectationFixtureReplace(t *testing.T, a *LabConfigArtifact, raw []byte) *LabConfigArtifact {
	t.Helper(); descriptor := a.Descriptor(); descriptor.Bytes = len(raw); descriptor.SHA256 = labConfigHash(raw)
	return &LabConfigArtifact{labConfigArtifactCore: &labConfigArtifactCore{raw: bytes.Clone(raw), descriptor: descriptor}}
}
func TestLabExpectationBridgeUsesActualAdmittedArtifactAndOwnsOutput(t *testing.T) {
	a := labConfigTestBuild(t, labConfigTestSpec()); before := a.Bytes()
	e, err := labExpectationForArtifact(a); if err != nil { t.Fatal("admitted artifact projection rejected") }
	first, err := e.ProjectionSHA256(); if err != nil || len(first) != 64 { t.Fatal("missing expected projection digest") }
	copyOfBody := a.Bytes(); copyOfBody[0] ^= 1
	second, err := e.ProjectionSHA256(); if err != nil || first != second || !bytes.Equal(a.Bytes(), before) { t.Fatal("owned expectation or artifact aliased") }
	for _, value := range []any{e, &e} { raw, err := json.Marshal(value); if err != nil || strings.Contains(string(raw), labConfigTestSpec().ControllerSecret) { t.Fatal("private source exposed") } }
}
func TestLabExpectationBridgeRejectsNilBlockedCorruptAndZeroArtifact(t *testing.T) {
	var absent *LabConfigArtifact
	for _, a := range []*LabConfigArtifact{absent, {}, labConfigTestBuild(t, labConfigTestSpec())} {
		if a != nil && a.labConfigArtifactCore != nil { a.descriptor.SHA256 = strings.Repeat("0", 64) }
		if _, err := labExpectationForArtifact(a); err == nil { t.Fatal("unadmitted source produced an expectation") }
	}
	spec := labConfigTestSpec(); spec.Draft.Businesses[0].FailuresToSwitch = 2
	if _, err := labExpectationForArtifact(labConfigTestBuild(t, spec)); err == nil { t.Fatal("external policy obligation silently disappeared") }
}
func TestLabExpectationBridgeRejectsNoncanonicalAndUnsupportedSource(t *testing.T) {
	a := labConfigTestBuild(t, labConfigTestSpec())
	for _, raw := range [][]byte{append(a.Bytes(), []byte("# not generated\n")...), append(a.Bytes(), []byte("unknown: private\n")...), bytes.Replace(a.Bytes(), []byte("allow-lan: false"), []byte("allow-lan: true"), 1)} {
		candidate := expectationFixtureReplace(t, a, raw)
		if candidate.AdmissionError() != nil { t.Fatal("self-consistent model digest failed before bridge check") }
		if _, err := labExpectationForArtifact(candidate); err == nil { t.Fatal("noncanonical or unsupported body accepted") }
	}
	for _,kind:=range []string{"proxy-order","group-order"}{
		var value labRawConfig;if yaml.Unmarshal(a.Bytes(),&value)!=nil{t.Fatal("source order fixture decode")}
		if kind=="proxy-order"{value.Proxies[0],value.Proxies[1]=value.Proxies[1],value.Proxies[0]}else{value.Groups[0],value.Groups[1]=value.Groups[1],value.Groups[0]}
		raw,err:=yaml.Marshal(value);if err!=nil{t.Fatal("source order fixture encode")};candidate:=expectationFixtureReplace(t,a,raw)
		if candidate.AdmissionError()!=nil{t.Fatal("source order fixture failed before bridge")}
		if _,err:=labExpectationForArtifact(candidate);err==nil{t.Fatal("bridge sorted unsupported original source instead of rejecting")}
	}
}
func TestLabExpectationBridgePreservesRuleAndMemberOrder(t *testing.T) {
	spec := labConfigTestSpec(); a := labConfigTestBuild(t, spec); first, err := labExpectationForArtifact(a); if err != nil { t.Fatal(err) }
	before, _ := first.ProjectionSHA256()
	spec.Draft.Businesses[0], spec.Draft.Businesses[1] = spec.Draft.Businesses[1], spec.Draft.Businesses[0]
	second, err := labExpectationForArtifact(labConfigTestBuild(t, spec)); if err != nil { t.Fatal(err) }; after, _ := second.ProjectionSHA256()
	if before == after { t.Fatal("ordered rules collapsed") }
	spec = labConfigTestSpec(); spec.Draft.Pools[0].Members[0], spec.Draft.Pools[0].Members[1] = spec.Draft.Pools[0].Members[1], spec.Draft.Pools[0].Members[0]
	third, err := labExpectationForArtifact(labConfigTestBuild(t, spec)); if err != nil { t.Fatal(err) }; members, _ := third.ProjectionSHA256()
	if members == before { t.Fatal("selector member order collapsed") }
}
func TestLabExpectationBridgeRejectsPrivateEndpointChangesOutsideBuilderDomain(t *testing.T) {
	a := labConfigTestBuild(t, labConfigTestSpec()); var value labRawConfig
	if yaml.Unmarshal(a.Bytes(), &value) != nil { t.Fatal("fixture shape") }; value.Proxies[0].Server = "192.0.2.1"
	raw, err := yaml.Marshal(value); if err != nil { t.Fatal("fixture encoding") }
	if _, err := labExpectationForArtifact(expectationFixtureReplace(t, a, raw)); err == nil || strings.Contains(fmt.Sprint(err), "192.0.2.1") { t.Fatal("invalid private endpoint accepted or exposed") }
	if yaml.Unmarshal(a.Bytes(),&value)!=nil{t.Fatal("duplicate endpoint fixture decode")}
	value.Proxies[1].Server,value.Proxies[1].Port=value.Proxies[0].Server,value.Proxies[0].Port
	raw,err=yaml.Marshal(value);if err!=nil{t.Fatal("duplicate endpoint fixture encode")};candidate:=expectationFixtureReplace(t,a,raw)
	if candidate.AdmissionError()!=nil{t.Fatal("duplicate endpoint self-consistent fixture failed before bridge")}
	if _,err:=labExpectationForArtifact(candidate);err==nil{t.Fatal("different node names admitted the same private endpoint")}
}
