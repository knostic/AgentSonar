package sai

import (
	"compress/gzip"
	"encoding/gob"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type Agent struct {
	Name    string
	Process string
	Domains []string
}

type Overrides struct {
	agents  []Agent
	noise   []string
	mu      sync.RWMutex
}

func NewOverrides() *Overrides {
	return &Overrides{}
}

func (o *Overrides) AddAgent(name, process string, domains []string) {
	o.mu.Lock()
	defer o.mu.Unlock()

	for i, a := range o.agents {
		if a.Name == name {
			o.agents[i].Process = process
			o.agents[i].Domains = append(o.agents[i].Domains, domains...)
			return
		}
	}
	o.agents = append(o.agents, Agent{Name: name, Process: process, Domains: domains})
}

func (o *Overrides) AddAgentDomain(name, domain string) {
	o.mu.Lock()
	defer o.mu.Unlock()

	for i, a := range o.agents {
		if a.Name == name {
			for _, d := range a.Domains {
				if d == domain {
					return
				}
			}
			o.agents[i].Domains = append(o.agents[i].Domains, domain)
			return
		}
	}
}

func (o *Overrides) RemoveAgent(name string) {
	o.mu.Lock()
	defer o.mu.Unlock()

	for i, a := range o.agents {
		if a.Name == name {
			o.agents = append(o.agents[:i], o.agents[i+1:]...)
			return
		}
	}
}

func (o *Overrides) ListAgents() []Agent {
	o.mu.RLock()
	defer o.mu.RUnlock()

	result := make([]Agent, len(o.agents))
	copy(result, o.agents)
	return result
}

func (o *Overrides) GetAgent(name string) *Agent {
	o.mu.RLock()
	defer o.mu.RUnlock()

	for _, a := range o.agents {
		if a.Name == name {
			cp := a
			return &cp
		}
	}
	return nil
}

func (o *Overrides) MatchAgent(process, domain string) string {
	process = strings.ToLower(process)
	domain = normalizeDomain(domain)

	o.mu.RLock()
	defer o.mu.RUnlock()

	for _, a := range o.agents {
		if !matchPattern(process, strings.ToLower(a.Process)) {
			continue
		}
		for _, d := range a.Domains {
			if matchPattern(domain, strings.ToLower(d)) {
				return a.Name
			}
		}
	}
	return ""
}

func (o *Overrides) AddNoise(domain string) {
	domain = normalizeDomain(domain)
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, d := range o.noise {
		if d == domain {
			return
		}
	}
	o.noise = append(o.noise, domain)
}

func (o *Overrides) RemoveNoise(domain string) {
	domain = normalizeDomain(domain)
	o.mu.Lock()
	defer o.mu.Unlock()
	for i, d := range o.noise {
		if d == domain {
			o.noise = append(o.noise[:i], o.noise[i+1:]...)
			return
		}
	}
}

func (o *Overrides) ListNoise() []string {
	o.mu.RLock()
	defer o.mu.RUnlock()
	result := make([]string, len(o.noise))
	copy(result, o.noise)
	return result
}

func (o *Overrides) IsNoise(domain string) bool {
	domain = normalizeDomain(domain)
	o.mu.RLock()
	defer o.mu.RUnlock()

	for _, d := range o.noise {
		if d == domain || strings.HasSuffix(domain, "."+d) {
			return true
		}
	}
	return false
}

// Signals interface implementation
func (o *Overrides) IsNonAI(process, domain string) bool {
	return o.IsNoise(domain)
}

func (o *Overrides) IsNonAIDomain(domain string) bool {
	return o.IsNoise(domain)
}

type OverridesData struct {
	Agents []Agent
	Noise  []string
}

func (o *Overrides) Save(path string) error {
	o.mu.RLock()
	defer o.mu.RUnlock()

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	gzw := gzip.NewWriter(file)
	defer gzw.Close()

	data := OverridesData{
		Agents: o.agents,
		Noise:  o.noise,
	}

	return gob.NewEncoder(gzw).Encode(data)
}

func (o *Overrides) Load(path string) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	gzr, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gzr.Close()

	var data OverridesData
	if err := gob.NewDecoder(gzr).Decode(&data); err != nil {
		return err
	}

	o.agents = data.Agents
	o.noise = data.Noise
	return nil
}

func (o *Overrides) Export() OverridesData {
	o.mu.RLock()
	defer o.mu.RUnlock()

	agents := make([]Agent, len(o.agents))
	copy(agents, o.agents)

	noise := make([]string, len(o.noise))
	copy(noise, o.noise)

	return OverridesData{
		Agents: agents,
		Noise:  noise,
	}
}

func (o *Overrides) Import(data OverridesData) {
	o.mu.Lock()
	defer o.mu.Unlock()

	o.agents = make([]Agent, len(data.Agents))
	copy(o.agents, data.Agents)

	o.noise = make([]string, len(data.Noise))
	copy(o.noise, data.Noise)
}

func DefaultOverridesPath() string {
	if p := os.Getenv("SAI_OVERRIDES_PATH"); p != "" {
		return p
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "sai", "overrides.bin")
}

func OverridesFileExists() bool {
	_, err := os.Stat(DefaultOverridesPath())
	return err == nil
}

func matchPattern(s, pattern string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		return strings.HasSuffix(s, pattern[1:]) || s == pattern[2:]
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(s, pattern[:len(pattern)-1])
	}
	return s == pattern || strings.Contains(s, pattern)
}

func normalizeDomain(domain string) string {
	domain = strings.ToLower(domain)
	domain = strings.TrimPrefix(domain, "www.")
	return domain
}
