package overview

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"chengwang/internal/observation"
	"chengwang/internal/probeview"
)

var ErrInvalidProjection = errors.New("overview projection invalid")

type ObservationStatusSource interface{ Status() observation.Status }
type ProbeStatusSource interface{ Status() probeview.Status }
type SnapshotProvider interface {
	Snapshot(context.Context) (PublicSnapshot, error)
}

type Config struct {
	Mode                   string
	Observation            ObservationStatusSource
	Probes                 ProbeStatusSource
	SubscriptionConfigured bool
	Now                    func() time.Time
}

type Provider struct{ config Config }

func nilSource(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	}
	return false
}

// New performs no source reads. Configuration is not a health assertion.
func New(config Config) (*Provider, error) {
	if !safeMode(config.Mode) {
		return nil, ErrInvalidProjection
	}
	if nilSource(config.Observation) {
		config.Observation = nil
	}
	if nilSource(config.Probes) {
		config.Probes = nil
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Provider{config: config}, nil
}

// Snapshot only calls the two Status getters. They do not accept context, so
// cancellation is cooperative before/after calls, never a hard lock deadline.
func (p *Provider) Snapshot(ctx context.Context) (PublicSnapshot, error) {
	if p == nil || ctx == nil {
		return PublicSnapshot{}, ErrInvalidProjection
	}
	if err := ctx.Err(); err != nil {
		return PublicSnapshot{}, err
	}
	var observed observation.Status
	var probed probeview.Status
	if p.config.Observation != nil {
		observed = p.config.Observation.Status()
	}
	if err := ctx.Err(); err != nil {
		return PublicSnapshot{}, err
	}
	if p.config.Probes != nil {
		probed = p.config.Probes.Status()
	}
	if err := ctx.Err(); err != nil {
		return PublicSnapshot{}, err
	}
	now := p.config.Now().UTC()
	if err := ctx.Err(); err != nil {
		return PublicSnapshot{}, err
	}
	o, err := projectObservation(observed, now)
	if err != nil {
		return PublicSnapshot{}, ErrInvalidProjection
	}
	q := disabledProbe()
	if p.config.Probes != nil {
		q, err = projectProbe(probed, now)
		if err != nil {
			return PublicSnapshot{}, ErrInvalidProjection
		}
	}
	value := PublicSnapshot{Schema: Schema, DataSource: "live", GeneratedAt: now, Mode: p.config.Mode,
		ReadOnly: true, AdvisoryOnly: true, Observation: o, Probe: q,
		Subscription: SubscriptionSummary{Configured: p.config.SubscriptionConfigured, InventoryState: "protected_not_read"},
		Unsupported:  Unsupported{Businesses: true, NodePools: true, EndToEndDNS: true, DeviceInventory: true, TrafficTopology: true}}
	value.Coverage = coverageFor(o, q)
	if err := Validate(value); err != nil {
		return PublicSnapshot{}, ErrInvalidProjection
	}
	if err := ctx.Err(); err != nil {
		return PublicSnapshot{}, err
	}
	return value, nil
}

func safeMode(mode string) bool {
	if mode == "" || len(mode) > 64 || !utf8.ValidString(mode) || strings.TrimSpace(mode) != mode {
		return false
	}
	for _, r := range mode {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

func copyTime(value *time.Time) *time.Time {
	if value == nil || value.IsZero() {
		return nil
	}
	copy := value.UTC()
	return &copy
}

func validTime(value time.Time) bool {
	_, offset := value.Zone()
	return !value.IsZero() && value.Year() >= 0 && value.Year() <= 9999 && offset == 0
}

func validOptional(value *time.Time, now time.Time, allowFuture bool) bool {
	return value == nil || validTime(*value) && (allowFuture || !value.After(now))
}

func validWindow(observed, expires *time.Time, now time.Time, allowFuture bool) bool {
	if !validOptional(observed, now, allowFuture) || expires != nil && !validTime(*expires) {
		return false
	}
	return expires == nil || observed != nil && expires.After(*observed)
}

func current(observed, expires *time.Time, now time.Time) bool {
	return observed != nil && expires != nil && !observed.After(now) && now.Before(*expires) && expires.After(*observed)
}

func stateKnown(state string) bool {
	switch state {
	case "unknown", "available", "degraded", "unavailable":
		return true
	}
	return false
}

func reasonKnown(reason string) bool {
	switch reason {
	case "not_configured", "no_current_evidence", "cache_current", "evidence_stale", "read_failed", "worker_stopped", "clock_untrusted", "storage_unhealthy":
		return true
	}
	return false
}

func layerRoleReason(layer Layer, role string) bool {
	if layer.State == "available" {
		return layer.Reason == "cache_current"
	}
	if layer.State == "unknown" {
		if layer.Reason == "not_configured" || layer.Reason == "no_current_evidence" {
			return true
		}
		return role == "controller" && (layer.Reason == "worker_stopped" || layer.Reason == "clock_untrusted")
	}
	switch role {
	case "controller":
		return layer.State == "degraded" && layer.Reason == "evidence_stale" || layer.State == "unavailable" && layer.Reason == "read_failed"
	case "storage":
		return (layer.State == "degraded" || layer.State == "unavailable") && layer.Reason == "storage_unhealthy"
	case "clock":
		return (layer.State == "degraded" || layer.State == "unavailable") && layer.Reason == "clock_untrusted"
	}
	return false
}

func count(value int) bool        { return value >= 0 && value <= 2147483647 }
func unknown(reason string) Layer { return Layer{State: "unknown", Reason: reason} }
func disabledObservation() ObservationSummary {
	return ObservationSummary{Controller: unknown("not_configured"), Storage: unknown("not_configured"), Clock: unknown("not_configured")}
}
func disabledProbe() ProbeSummary {
	return ProbeSummary{State: "disabled", Reason: "disabled", CoverageState: "unavailable"}
}

func projectLayer(source observation.Layer, role string) (Layer, error) {
	state := string(source.State)
	if !stateKnown(state) {
		return Layer{}, ErrInvalidProjection
	}
	layer := Layer{State: state, ObservedAt: copyTime(source.ObservedAt), ExpiresAt: copyTime(source.ExpiresAt)}
	switch state {
	case "unknown":
		layer.Reason = "no_current_evidence"
	case "available":
		layer.Reason = "cache_current"
	case "degraded":
		layer.Reason = "evidence_stale"
	case "unavailable":
		layer.Reason = "read_failed"
	}
	if role == "storage" && (state == "degraded" || state == "unavailable") {
		layer.Reason = "storage_unhealthy"
	}
	if role == "clock" && (state == "degraded" || state == "unavailable") {
		layer.Reason = "clock_untrusted"
	}
	return layer, nil
}

func projectObservation(source observation.Status, now time.Time) (ObservationSummary, error) {
	if !source.Configured {
		return disabledObservation(), nil
	}
	if source.Mode != "passive_read_only" || !count(source.ConsecutiveFailures) || source.Fresh && source.Stale {
		return ObservationSummary{}, ErrInvalidProjection
	}
	controller, err := projectLayer(source.Controller, "controller")
	if err != nil {
		return ObservationSummary{}, err
	}
	storage, err := projectLayer(source.Storage, "storage")
	if err != nil {
		return ObservationSummary{}, err
	}
	clock, err := projectLayer(source.Clock, "clock")
	if err != nil {
		return ObservationSummary{}, err
	}
	value := ObservationSummary{Configured: true, Running: source.Running, Stale: source.Stale,
		LastAttemptAt: copyTime(source.LastAttemptAt), LastSuccessAt: copyTime(source.LastSuccessAt), ConsecutiveFailures: source.ConsecutiveFailures,
		Controller: controller, Storage: storage, Clock: clock}
	if source.Fresh && (source.ConsecutiveFailures != 0 || controller.State != "available" || clock.State != "available" ||
		value.LastSuccessAt == nil || controller.ObservedAt == nil || controller.ExpiresAt == nil || !value.LastSuccessAt.Equal(*controller.ObservedAt)) {
		return ObservationSummary{}, ErrInvalidProjection
	}
	value.Fresh = source.Fresh && source.Running && clock.State == "available" && controller.State == "available" && current(controller.ObservedAt, controller.ExpiresAt, now)
	value.Stale = value.Stale || value.LastSuccessAt != nil && !value.Fresh
	switch {
	case clock.State != "available":
		value.Controller.State, value.Controller.Reason = "unknown", "clock_untrusted"
	case !source.Running:
		value.Controller.State, value.Controller.Reason = "unknown", "worker_stopped"
	case value.Fresh:
	case value.Stale && controller.ObservedAt != nil:
		value.Controller.State, value.Controller.Reason = "degraded", "evidence_stale"
	case controller.State == "unavailable" && current(controller.ObservedAt, controller.ExpiresAt, now):
	default:
		value.Controller.State, value.Controller.Reason = "unknown", "no_current_evidence"
	}
	return value, nil
}

func probeReason(reason string) bool {
	switch reason {
	case "disabled", "not_started", "ok", "partial_coverage", "no_current_evidence", "evidence_expired", "content_rejected", "clock_rollback", "stopped", "cache_expired", "platform_unsupported", "limit_rejected", "storage_rejected", "read_unavailable":
		return true
	}
	return false
}

func probeState(state string) bool {
	switch state {
	case "disabled", "pending", "unknown", "partial", "ready":
		return true
	}
	return false
}

func probeStateReason(state, reason string) bool {
	switch state {
	case "disabled":
		return reason == "disabled"
	case "pending":
		return reason == "not_started"
	case "ready":
		return reason == "ok"
	case "partial":
		return reason == "partial_coverage" || reason == "no_current_evidence" || reason == "evidence_expired"
	case "unknown":
		return probeReason(reason) && reason != "disabled" && reason != "not_started" && reason != "ok" && reason != "partial_coverage"
	}
	return false
}

func validCounts(c ProbeCoverage) bool {
	for _, value := range []int{c.DeclaredTargets, c.TargetsWithSamples, c.TargetsMissing, c.RetainedSamples, c.ValidTotal, c.ExpiredTotal, c.EligibleTotal, c.RejectedTotal} {
		if !count(value) {
			return false
		}
	}
	return c.DeclaredTargets <= 256 && c.TargetsWithSamples <= c.DeclaredTargets && c.TargetsMissing == c.DeclaredTargets-c.TargetsWithSamples &&
		c.RetainedSamples <= 200 && c.ExpiredTotal <= c.ValidTotal && c.EligibleTotal == c.ValidTotal-c.ExpiredTotal && c.RetainedSamples <= c.EligibleTotal
}

func projectProbe(source probeview.Status, now time.Time) (ProbeSummary, error) {
	if source.Schema != "chengwang.probe-view-status/v1" || !source.AdvisoryOnly || !probeStateReason(source.State, source.Reason) {
		return ProbeSummary{}, ErrInvalidProjection
	}
	c := ProbeCoverage(source.Coverage)
	if !validCounts(c) {
		return ProbeSummary{}, ErrInvalidProjection
	}
	if !source.Configured {
		return disabledProbe(), nil
	}
	value := ProbeSummary{Configured: true, Running: source.Running, State: source.State, Reason: source.Reason,
		ClockHealthy: source.ClockHealthy, StorageHealthy: source.StorageHealthy, CachedAt: copyTime(source.CachedAt), ExpiresAt: copyTime(source.ExpiresAt), CoverageState: "unavailable"}
	if source.State == "disabled" || (source.State == "ready" || source.State == "partial") && (value.CachedAt == nil || value.ExpiresAt == nil) {
		return ProbeSummary{}, ErrInvalidProjection
	}
	switch {
	case !source.ClockHealthy:
		value.State, value.Reason = "unknown", "clock_rollback"
	case !source.Running && source.State != "pending":
		value.State, value.Reason = "unknown", "stopped"
	case !source.StorageHealthy && (source.State == "ready" || source.State == "partial"):
		value.State, value.Reason = "unknown", "content_rejected"
	case value.ExpiresAt != nil && !now.Before(*value.ExpiresAt):
		value.State, value.Reason = "unknown", "cache_expired"
	}
	if value.Running && value.ClockHealthy && value.StorageHealthy && (value.State == "ready" || value.State == "partial") && current(value.CachedAt, value.ExpiresAt, now) {
		value.CoverageState, value.Coverage = "current", &c
	}
	return value, nil
}

func coverageFor(o ObservationSummary, p ProbeSummary) Coverage {
	missing := make([]string, 0, 7)
	if !o.Fresh {
		missing = append(missing, "controller_observation")
	}
	if p.CoverageState != "current" {
		missing = append(missing, "probe_readback")
	}
	missing = append(missing, "businesses", "node_pools", "end_to_end_dns", "device_inventory", "traffic_topology")
	state := "none"
	if o.Fresh || p.CoverageState == "current" {
		state = "partial"
	}
	return Coverage{State: state, Missing: missing}
}

// Validate also protects HTTP from an alternate provider returning a malformed
// public DTO. It is a display contract, not proof of upstream business health.
func Validate(value PublicSnapshot) error {
	if value.Schema != Schema || value.DataSource != "live" || !validTime(value.GeneratedAt) || !safeMode(value.Mode) || !value.ReadOnly || !value.AdvisoryOnly ||
		value.Unsupported != (Unsupported{true, true, true, true, true}) || value.Subscription.InventoryState != "protected_not_read" || value.Subscription.SourceCount != nil || value.Subscription.NodeCount != nil {
		return ErrInvalidProjection
	}
	o, p, now := value.Observation, value.Probe, value.GeneratedAt
	if !count(o.ConsecutiveFailures) || o.Fresh && o.Stale {
		return ErrInvalidProjection
	}
	allowFuture := o.Clock.State == "unavailable"
	if !validOptional(o.LastAttemptAt, now, allowFuture) || !validOptional(o.LastSuccessAt, now, allowFuture) {
		return ErrInvalidProjection
	}
	for _, layer := range []Layer{o.Controller, o.Storage, o.Clock} {
		if !stateKnown(layer.State) || !reasonKnown(layer.Reason) || !validWindow(layer.ObservedAt, layer.ExpiresAt, now, allowFuture) {
			return ErrInvalidProjection
		}
	}
	if !layerRoleReason(o.Controller, "controller") || !layerRoleReason(o.Storage, "storage") || !layerRoleReason(o.Clock, "clock") {
		return ErrInvalidProjection
	}
	if !o.Configured && !reflect.DeepEqual(o, disabledObservation()) {
		return ErrInvalidProjection
	}
	if o.Controller.State == "available" && !o.Fresh {
		return ErrInvalidProjection
	}
	if o.Fresh && (!o.Configured || !o.Running || o.Clock.State != "available" || o.Controller.State != "available" || o.LastSuccessAt == nil || !current(o.Controller.ObservedAt, o.Controller.ExpiresAt, now) || !o.LastSuccessAt.Equal(*o.Controller.ObservedAt) || o.ConsecutiveFailures != 0) {
		return ErrInvalidProjection
	}
	if (!o.Running || o.Clock.State != "available") && (o.Fresh || o.Controller.State != "unknown") {
		return ErrInvalidProjection
	}
	if !probeState(p.State) || !probeStateReason(p.State, p.Reason) || !validWindow(p.CachedAt, p.ExpiresAt, now, !p.ClockHealthy) {
		return ErrInvalidProjection
	}
	if !p.Configured && !reflect.DeepEqual(p, disabledProbe()) {
		return ErrInvalidProjection
	}
	if p.Configured && (p.State == "disabled" || (p.State == "ready" || p.State == "partial") && (p.CachedAt == nil || p.ExpiresAt == nil)) {
		return ErrInvalidProjection
	}
	eligible := p.Configured && p.Running && p.ClockHealthy && p.StorageHealthy && (p.State == "ready" || p.State == "partial") && current(p.CachedAt, p.ExpiresAt, now)
	if eligible {
		if p.CoverageState != "current" || p.Coverage == nil || !validCounts(*p.Coverage) {
			return ErrInvalidProjection
		}
	} else if p.CoverageState != "unavailable" || p.Coverage != nil || (!p.ClockHealthy && p.State != "unknown" && p.State != "disabled") {
		return ErrInvalidProjection
	}
	expected := coverageFor(o, p)
	if !reflect.DeepEqual(value.Coverage, expected) {
		return ErrInvalidProjection
	}
	return nil
}
