package kernel

import (
	"fmt"
	"sort"
	"sync"
)

type Support string

const (
	Native      Support = "native"
	Adapted     Support = "adapter"
	Unsupported Support = "unsupported"
)

type Capability struct {
	Name    string  `json:"name"`
	Support Support `json:"support"`
	Note    string  `json:"note,omitempty"`
}

type Descriptor struct {
	ID           string       `json:"id"`
	DisplayName  string       `json:"displayName"`
	ConfigFormat string       `json:"configFormat"`
	Capabilities []Capability `json:"capabilities"`
}

type Adapter interface {
	Descriptor() Descriptor
	Validate(config []byte) error
	Compile(desiredState []byte) ([]byte, error)
}

type Registry struct {
	mu       sync.RWMutex
	adapters map[string]Adapter
}

func NewRegistry() *Registry { return &Registry{adapters: make(map[string]Adapter)} }

func (r *Registry) Register(adapter Adapter) error {
	if adapter == nil {
		return fmt.Errorf("adapter is nil")
	}
	descriptor := adapter.Descriptor()
	if descriptor.ID == "" || descriptor.DisplayName == "" {
		return fmt.Errorf("adapter descriptor is incomplete")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.adapters[descriptor.ID]; exists {
		return fmt.Errorf("adapter %q already registered", descriptor.ID)
	}
	r.adapters[descriptor.ID] = adapter
	return nil
}

func (r *Registry) Get(id string) (Adapter, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	adapter, ok := r.adapters[id]
	return adapter, ok
}

func (r *Registry) Descriptors() []Descriptor {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]Descriptor, 0, len(r.adapters))
	for _, adapter := range r.adapters {
		result = append(result, adapter.Descriptor())
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

func KnownCapabilities() []string {
	return []string{
		"shadowsocks", "vmess", "vless", "trojan", "hysteria2", "tuic", "anytls", "wireguard",
		"socks", "http", "tcp", "websocket", "grpc", "http2", "quic", "reality",
		"tun", "tproxy", "redir", "rule-provider", "geosite", "geoip", "dns-routing", "chain-proxy", "multiplex",
	}
}
