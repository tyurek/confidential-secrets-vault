package main

import (
	"sort"
	"sync"
)

// store is the prototype's RAM-only secret store, keyed by (repo, name). The
// repo is the tenant key (see design/secrets-vault-prototype.md): a secret is
// released to any workload whose attested provenance matches the repo. Values
// never touch disk and do not survive a restart.
type store struct {
	mu   sync.RWMutex
	data map[string]map[string]string // repo -> name -> value
}

func newStore() *store {
	return &store{data: make(map[string]map[string]string)}
}

func (s *store) put(repo, name, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data[repo] == nil {
		s.data[repo] = make(map[string]string)
	}
	s.data[repo][name] = value
}

func (s *store) names(repo string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	names := make([]string, 0, len(s.data[repo]))
	for n := range s.data[repo] {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func (s *store) delete(repo, name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.data[repo][name]; !ok {
		return false
	}
	delete(s.data[repo], name)
	return true
}

// get returns the requested secrets for a repo, skipping names it doesn't hold.
// Used by the release path (/fetch) once provenance is verified.
func (s *store) get(repo string, names []string) map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]string, len(names))
	for _, n := range names {
		if v, ok := s.data[repo][n]; ok {
			out[n] = v
		}
	}
	return out
}
