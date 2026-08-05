package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	ErrNotFound     = errors.New("descriptor not found")
	ErrPolicyDenied = errors.New("policy denied")
)

type PrincipalChain struct {
	HumanSubject string `json:"human_subject"`
	HumanEmail   string `json:"human_email,omitempty"`
	Authn        string `json:"authn"`
	Source       string `json:"source"`
}

func principalFromSession(session Session) PrincipalChain {
	return PrincipalChain{
		HumanSubject: session.Subject,
		HumanEmail:   session.Email,
		Authn:        "zitadel_oidc",
		Source:       "janus_web",
	}
}

type SecretProvider interface {
	Name() string
	Find(ref string) (SecretDescriptor, bool)
}

type AgeMetadataProvider struct {
	store *Store
}

func (p AgeMetadataProvider) Name() string {
	return "agenix"
}

func (p AgeMetadataProvider) Find(ref string) (SecretDescriptor, bool) {
	return p.store.FindDescriptor(ref)
}

type Broker struct {
	provider    SecretProvider
	store       *Store
	scopePolicy ScopePolicy
}

func NewBroker(store *Store) *Broker {
	return &Broker{
		provider:    AgeMetadataProvider{store: store},
		store:       store,
		scopePolicy: ScopePolicy{AllowedScopes: map[string]bool{"csb1": true}, Strict: true},
	}
}

func (b *Broker) WithScopePolicy(policy ScopePolicy) *Broker {
	b.scopePolicy = policy
	return b
}

func (b *Broker) Descriptors(_ PrincipalChain) []SecretDescriptor {
	return b.scopePolicy.Filter(b.store.Descriptors())
}

type HandleRequest struct {
	Ref    string `json:"ref"`
	Reason string `json:"reason,omitempty"`
}

type SecretHandle struct {
	HandleID      string    `json:"handle_id"`
	SecretRef     string    `json:"secret_ref"`
	DisplayName   string    `json:"display_name"`
	Provider      string    `json:"provider"`
	ExpiresAt     time.Time `json:"expires_at"`
	Capabilities  []string  `json:"capabilities"`
	ValueReturned bool      `json:"value_returned"`
}

func (b *Broker) ResolveHandle(principal PrincipalChain, req HandleRequest) (SecretHandle, error) {
	desc, ok := b.provider.Find(req.Ref)
	if !ok {
		return SecretHandle{}, ErrNotFound
	}
	if !b.scopePolicy.Allows(desc.Scope) {
		return SecretHandle{}, ErrPolicyDenied
	}
	if blocked, reason := DescriptorBlocksNormalUse(desc); blocked {
		return SecretHandle{}, fmt.Errorf("%w: %s", ErrPolicyDenied, reason)
	}
	if principal.HumanSubject == "" {
		return SecretHandle{}, ErrPolicyDenied
	}
	reason := stringsTrim(req.Reason)
	if reason == "" {
		return SecretHandle{}, fmt.Errorf("%w: reason required", ErrPolicyDenied)
	}
	if len(reason) > 160 || containsControl(reason) {
		return SecretHandle{}, fmt.Errorf("%w: reason must be one line and at most 160 characters", ErrPolicyDenied)
	}
	return SecretHandle{
		HandleID:      "h_" + randomToken(18),
		SecretRef:     desc.ID,
		DisplayName:   desc.DisplayName,
		Provider:      desc.Provider,
		ExpiresAt:     time.Now().UTC().Add(5 * time.Minute),
		Capabilities:  []string{"describe", "permit_request"},
		ValueReturned: false,
	}, nil
}

type PermitRequest struct {
	Ref         string `json:"ref"`
	Action      string `json:"action"`
	Destination string `json:"destination,omitempty"`
	Reason      string `json:"reason"`
}

type Permit struct {
	ID               string    `json:"id"`
	SecretRef        string    `json:"secret_ref"`
	Action           string    `json:"action"`
	Destination      string    `json:"destination,omitempty"`
	Reason           string    `json:"reason"`
	Status           string    `json:"status"`
	DenialReason     string    `json:"denial_reason,omitempty"`
	ExecutionAllowed bool      `json:"execution_allowed"`
	ValueReturned    bool      `json:"value_returned"`
	PrincipalHash    string    `json:"principal_hash"`
	CreatedAt        time.Time `json:"created_at"`
	ExpiresAt        time.Time `json:"expires_at"`
}

type PermitRunResult struct {
	PermitID       string `json:"permit_id"`
	Status         string `json:"status"`
	Reason         string `json:"reason"`
	OutputScrubbed bool   `json:"output_scrubbed"`
	ValueReturned  bool   `json:"value_returned"`
}

func (b *Broker) CreatePermit(principal PrincipalChain, req PermitRequest) (Permit, error) {
	desc, ok := b.provider.Find(req.Ref)
	if !ok {
		return Permit{}, ErrNotFound
	}
	if !b.scopePolicy.Allows(desc.Scope) {
		return Permit{}, ErrPolicyDenied
	}
	if blocked, reason := DescriptorBlocksNormalUse(desc); blocked {
		return Permit{}, fmt.Errorf("%w: %s", ErrPolicyDenied, reason)
	}
	if principal.HumanSubject == "" {
		return Permit{}, ErrPolicyDenied
	}
	reason := stringsTrim(req.Reason)
	if reason == "" {
		return Permit{}, fmt.Errorf("%w: reason required", ErrPolicyDenied)
	}
	if len(reason) > 160 || containsControl(reason) {
		return Permit{}, fmt.Errorf("%w: reason must be one line and at most 160 characters", ErrPolicyDenied)
	}
	destination := stringsTrim(req.Destination)
	if len(destination) > 120 || containsControl(destination) {
		return Permit{}, fmt.Errorf("%w: destination must be one line and at most 120 characters", ErrPolicyDenied)
	}

	action := stringsTrim(req.Action)
	if action == "" {
		action = "metadata_use"
	}

	permit := Permit{
		ID:            "p_" + randomToken(18),
		SecretRef:     desc.ID,
		Action:        action,
		Destination:   destination,
		Reason:        reason,
		Status:        "approved_metadata_only",
		ValueReturned: false,
		PrincipalHash: actorHash(principal.HumanSubject),
		CreatedAt:     time.Now().UTC(),
		ExpiresAt:     time.Now().UTC().Add(10 * time.Minute),
	}

	switch action {
	case "metadata_use", "resolve_handle":
		permit.ExecutionAllowed = false
		permit.DenialReason = "no execution connector configured in V1.1"
	default:
		permit.Status = "denied"
		permit.DenialReason = "unsupported action"
	}
	return permit, nil
}

func RunPermit(permit Permit) PermitRunResult {
	if time.Now().UTC().After(permit.ExpiresAt) {
		return PermitRunResult{
			PermitID:       permit.ID,
			Status:         "denied",
			Reason:         "permit expired",
			OutputScrubbed: true,
			ValueReturned:  false,
		}
	}
	if !permit.ExecutionAllowed {
		reason := permit.DenialReason
		if reason == "" {
			reason = "execution is not enabled for this permit"
		}
		return PermitRunResult{
			PermitID:       permit.ID,
			Status:         "not_executed",
			Reason:         reason,
			OutputScrubbed: true,
			ValueReturned:  false,
		}
	}
	return PermitRunResult{
		PermitID:       permit.ID,
		Status:         "not_executed",
		Reason:         "execution connector intentionally absent in V1.1",
		OutputScrubbed: true,
		ValueReturned:  false,
	}
}

type PermitStore struct {
	mu      sync.RWMutex
	file    string
	permits map[string]Permit
	persist func(string, permitStoreSnapshot) error
}

type PermitPosture struct {
	Count         int  `json:"count"`
	Persisted     bool `json:"persisted"`
	ValueReturned bool `json:"value_returned"`
}

type permitStoreSnapshot struct {
	Version       int      `json:"version"`
	Permits       []Permit `json:"permits"`
	ValueReturned bool     `json:"value_returned"`
}

func NewPermitStore(dataDir string) (*PermitStore, error) {
	store := &PermitStore{
		permits: make(map[string]Permit),
		persist: persistPermitStoreSnapshot,
	}
	if strings.TrimSpace(dataDir) == "" {
		return store, nil
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	store.file = filepath.Join(dataDir, "permits.json")
	if err := store.load(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *PermitStore) load() error {
	raw, err := os.ReadFile(s.file)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(raw)) == "" {
		return nil
	}
	var snapshot permitStoreSnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return err
	}
	for _, permit := range snapshot.Permits {
		if strings.TrimSpace(permit.ID) != "" {
			permit.ValueReturned = false
			s.permits[permit.ID] = permit
		}
	}
	return nil
}

func (s *PermitStore) Put(permit Permit) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	permit.ValueReturned = false
	candidate := clonePermits(s.permits)
	candidate[permit.ID] = permit
	if s.file != "" {
		if err := s.persist(s.file, permitSnapshot(candidate)); err != nil {
			return err
		}
	}
	s.permits = candidate
	return nil
}

func clonePermits(permits map[string]Permit) map[string]Permit {
	cloned := make(map[string]Permit, len(permits))
	for id, permit := range permits {
		permit.ValueReturned = false
		cloned[id] = permit
	}
	return cloned
}

func permitSnapshot(permits map[string]Permit) permitStoreSnapshot {
	ordered := make([]Permit, 0, len(permits))
	for _, permit := range permits {
		permit.ValueReturned = false
		ordered = append(ordered, permit)
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].CreatedAt.Equal(ordered[j].CreatedAt) {
			return ordered[i].ID < ordered[j].ID
		}
		return ordered[i].CreatedAt.After(ordered[j].CreatedAt)
	})
	return permitStoreSnapshot{
		Version:       1,
		Permits:       ordered,
		ValueReturned: false,
	}
}

func persistPermitStoreSnapshot(path string, snapshot permitStoreSnapshot) error {
	raw, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return atomicWritePrivateFile(path, raw)
}

func (s *PermitStore) Get(id string) (Permit, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	permit, ok := s.permits[id]
	return permit, ok
}

func (s *PermitStore) Recent(limit int) []Permit {
	s.mu.RLock()
	defer s.mu.RUnlock()
	permits := make([]Permit, 0, len(s.permits))
	for _, permit := range s.permits {
		permits = append(permits, permit)
	}
	sort.Slice(permits, func(i, j int) bool {
		return permits[i].CreatedAt.After(permits[j].CreatedAt)
	})
	if limit > 0 && len(permits) > limit {
		permits = permits[:limit]
	}
	return permits
}

func (s *PermitStore) Posture() PermitPosture {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return PermitPosture{
		Count:         len(s.permits),
		Persisted:     s.file != "",
		ValueReturned: false,
	}
}

func stringsTrim(value string) string {
	return strings.TrimSpace(value)
}
