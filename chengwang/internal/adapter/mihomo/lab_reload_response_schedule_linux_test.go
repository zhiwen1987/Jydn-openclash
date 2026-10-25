//go:build linux && chengwang_mihomo_recovery_continuous_fault

package mihomo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type labReloadScheduleModelTransport struct{ calls atomic.Int32 }

func (m *labReloadScheduleModelTransport) RoundTrip(*http.Request) (*http.Response, error) {
	m.calls.Add(1)
	return &http.Response{StatusCode: http.StatusNoContent, Header: http.Header{"Content-Length": []string{"0"}},
		ContentLength: 0, Body: io.NopCloser(strings.NewReader(""))}, nil
}

func labReloadScheduleModelClient(t *testing.T, inner http.RoundTripper) *WriteClient {
	t.Helper()
	client, err := NewWriteClient("http://127.0.0.1:28412", strings.Repeat("s", 40), time.Second)
	if err != nil {
		t.Fatal("MODEL client")
	}
	client.httpClient.Transport = inner
	return client
}

func TestLabReloadResponseLossScheduleFixedThreeClientContractMODEL(t *testing.T) {
	root, err := BeginLabReloadResponseLossSchedule()
	if err != nil || root == nil {
		t.Fatal("MODEL root issue")
	}
	copyRoot := *root
	probe := labReloadScheduleModelClient(t, &labReloadScheduleModelTransport{})
	if _, err := copyRoot.Bind(probe); err == nil {
		t.Fatal("MODEL copied root bound client")
	}

	clients := make([]*WriteClient, 3)
	children := make([]*LabReloadResponseLossChild, 3)
	inners := make([]*labReloadScheduleModelTransport, 3)
	for i := range clients {
		inners[i] = &labReloadScheduleModelTransport{}
		clients[i] = labReloadScheduleModelClient(t, inners[i])
		children[i], err = root.Bind(clients[i])
		if err != nil || children[i] == nil {
			t.Fatalf("MODEL child %d bind", i+1)
		}
		result, reloadErr := clients[i].Reload(context.Background(), []byte("mixed-port: 28411\n"))
		if i == 1 {
			if reloadErr != nil || result.State != ReloadAcknowledged || !result.Dispatched || result.StatusCode != http.StatusNoContent {
				t.Fatal("MODEL middle ACK passthrough")
			}
		} else if !errors.Is(reloadErr, errReloadUnknown) || result.State != ReloadUnknown || !result.Dispatched || result.StatusCode != 0 {
			t.Fatal("MODEL LOSS did not become UNKNOWN")
		}
		if inners[i].calls.Load() != 1 {
			t.Fatal("MODEL child did not make exactly one inner call")
		}
		step, observeErr := children[i].Observe()
		if observeErr != nil || step.Sequence != i+1 || step.UnderlyingRoundTrips != 1 || step.Action != []string{"LOSS", "PASS", "LOSS"}[i] ||
			(step.Action == "LOSS" && (!step.Injected || step.State != "INJECTED")) ||
			(step.Action == "PASS" && (step.Injected || step.State != "PASSTHROUGH")) {
			t.Fatal("MODEL step observation")
		}
		foreign := &LabReloadResponseLossChild{core: children[i].core}
		if _, err := foreign.Observe(); err == nil {
			t.Fatal("MODEL copied child observed")
		}
		if _, err := root.Bind(clients[i]); err == nil {
			t.Fatal("MODEL rebound client")
		}
	}
	if _, err := clients[0].Reload(context.Background(), []byte("mixed-port: 28411\n")); err == nil || inners[0].calls.Load() != 1 {
		t.Fatal("MODEL child replay reached inner")
	}
	if _, err := root.Bind(labReloadScheduleModelClient(t, &labReloadScheduleModelTransport{})); err == nil {
		t.Fatal("MODEL fourth child issued")
	}
	observation, err := root.Observe()
	if err != nil || observation.State != "TERMINAL" || observation.BoundChildren != 3 ||
		observation.UnderlyingRoundTrips != 3 || observation.Injected != 2 || len(observation.Steps) != 3 {
		t.Fatal("MODEL terminal observation")
	}
	for _, value := range []any{root, children[0]} {
		raw, marshalErr := json.Marshal(value)
		formatted := fmt.Sprintf("%v|%+v|%#v", value, value, value)
		if marshalErr != nil || strings.Contains(string(raw), "28412") || strings.Contains(formatted, "28412") ||
			strings.Contains(string(raw), strings.Repeat("s", 40)) || strings.Contains(formatted, strings.Repeat("s", 40)) {
			t.Fatal("MODEL opaque value leaked target or credential")
		}
	}
	if root.Close() != nil {
		t.Fatal("MODEL close")
	}
	if _, err := BeginLabReloadResponseLossSchedule(); err == nil {
		t.Fatal("MODEL issuer reset")
	}
}
