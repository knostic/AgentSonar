package sai

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type FilterAgent struct {
	Name    string   `json:"name"`
	Process string   `json:"process"`
	Domains []string `json:"domains"`
}

type FilterSet struct {
	agents         []FilterAgent
	ignoredDomains []string
	nonAIFilter    *bloomFilter
	mu             sync.RWMutex
}

func NewFilterSet() *FilterSet {
	return &FilterSet{
		nonAIFilter: newBloomFilter(10000, 0.01),
	}
}

func (f *FilterSet) AddAgent(name, process string, domains []string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	for i, a := range f.agents {
		if a.Name == name {
			f.agents[i].Process = process
			f.agents[i].Domains = append(f.agents[i].Domains, domains...)
			return
		}
	}
	f.agents = append(f.agents, FilterAgent{Name: name, Process: process, Domains: domains})
}

func (f *FilterSet) AddAgentDomain(name, domain string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	for i, a := range f.agents {
		if a.Name == name {
			for _, d := range a.Domains {
				if d == domain {
					return
				}
			}
			f.agents[i].Domains = append(f.agents[i].Domains, domain)
			return
		}
	}
}

func (f *FilterSet) RemoveAgent(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	for i, a := range f.agents {
		if a.Name == name {
			f.agents = append(f.agents[:i], f.agents[i+1:]...)
			return
		}
	}
}

func (f *FilterSet) ListAgents() []FilterAgent {
	f.mu.RLock()
	defer f.mu.RUnlock()

	result := make([]FilterAgent, len(f.agents))
	copy(result, f.agents)
	return result
}

func (f *FilterSet) GetAgent(name string) *FilterAgent {
	f.mu.RLock()
	defer f.mu.RUnlock()

	for _, a := range f.agents {
		if a.Name == name {
			cp := a
			return &cp
		}
	}
	return nil
}

func (f *FilterSet) MatchAgent(process, domain string) string {
	process = strings.ToLower(process)
	domain = normalizeDomain(domain)

	f.mu.RLock()
	defer f.mu.RUnlock()

	for _, a := range f.agents {
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

func (f *FilterSet) AddNonAI(process, domain string) {
	key := filterKey(process, domain)
	f.mu.Lock()
	f.nonAIFilter.Add(key)
	f.mu.Unlock()
}

func (f *FilterSet) AddNonAIDomain(domain string) {
	domain = normalizeDomain(domain)
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, d := range f.ignoredDomains {
		if d == domain {
			return
		}
	}
	f.ignoredDomains = append(f.ignoredDomains, domain)
	f.nonAIFilter.Add(domain)
}

func (f *FilterSet) RemoveIgnoredDomain(domain string) {
	domain = normalizeDomain(domain)
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, d := range f.ignoredDomains {
		if d == domain {
			f.ignoredDomains = append(f.ignoredDomains[:i], f.ignoredDomains[i+1:]...)
			return
		}
	}
}

func (f *FilterSet) ListIgnoredDomains() []string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	result := make([]string, len(f.ignoredDomains))
	copy(result, f.ignoredDomains)
	return result
}

func (f *FilterSet) IsNonAI(process, domain string) bool {
	key := filterKey(process, domain)
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.nonAIFilter.Test(key)
}

func (f *FilterSet) IsNonAIDomain(domain string) bool {
	domain = normalizeDomain(domain)
	f.mu.RLock()
	defer f.mu.RUnlock()

	for _, d := range f.ignoredDomains {
		if d == domain || strings.HasSuffix(domain, "."+d) {
			return true
		}
	}

	if f.nonAIFilter.Test(domain) {
		return true
	}

	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts)-1; i++ {
		parent := strings.Join(parts[i:], ".")
		if f.nonAIFilter.Test(parent) {
			return true
		}
	}
	return false
}

func (f *FilterSet) Save(path string) error {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	agentsJSON, err := json.Marshal(f.agents)
	if err != nil {
		return err
	}

	lenBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBuf, uint32(len(agentsJSON)))
	if _, err := file.Write(lenBuf); err != nil {
		return err
	}
	if _, err := file.Write(agentsJSON); err != nil {
		return err
	}

	ignoredJSON, err := json.Marshal(f.ignoredDomains)
	if err != nil {
		return err
	}
	binary.LittleEndian.PutUint32(lenBuf, uint32(len(ignoredJSON)))
	if _, err := file.Write(lenBuf); err != nil {
		return err
	}
	if _, err := file.Write(ignoredJSON); err != nil {
		return err
	}

	return f.nonAIFilter.writeTo(file)
}

func (f *FilterSet) Load(path string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(file, lenBuf); err != nil {
		return err
	}
	agentsLen := binary.LittleEndian.Uint32(lenBuf)

	agentsJSON := make([]byte, agentsLen)
	if _, err := io.ReadFull(file, agentsJSON); err != nil {
		return err
	}
	if err := json.Unmarshal(agentsJSON, &f.agents); err != nil {
		return err
	}

	if _, err := io.ReadFull(file, lenBuf); err != nil {
		return err
	}
	nextVal := binary.LittleEndian.Uint32(lenBuf)

	// backwards compat: old format has bloom filter m value here (typically ~95000)
	// new format has ignored domains JSON length (typically small)
	if nextVal < 50000 {
		ignoredJSON := make([]byte, nextVal)
		if _, err := io.ReadFull(file, ignoredJSON); err != nil {
			return err
		}
		if err := json.Unmarshal(ignoredJSON, &f.ignoredDomains); err != nil {
			return err
		}
		nonAIFilter, err := readBloomFilter(file)
		if err != nil {
			return err
		}
		f.nonAIFilter = nonAIFilter
	} else {
		if _, err := io.ReadFull(file, lenBuf); err != nil {
			return err
		}
		k := int(binary.LittleEndian.Uint32(lenBuf))
		m := int(nextVal)
		bitset := make([]byte, (m+7)/8)
		if _, err := io.ReadFull(file, bitset); err != nil {
			return err
		}
		f.nonAIFilter = &bloomFilter{m: m, k: k, bitset: bitset}
	}

	return nil
}

func filterKey(process, domain string) string {
	return strings.ToLower(process) + ":" + normalizeDomain(domain)
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

func (bf *bloomFilter) writeTo(w io.Writer) error {
	header := make([]byte, 8)
	binary.LittleEndian.PutUint32(header[0:4], uint32(bf.m))
	binary.LittleEndian.PutUint32(header[4:8], uint32(bf.k))
	if _, err := w.Write(header); err != nil {
		return err
	}
	_, err := w.Write(bf.bitset)
	return err
}

func readBloomFilter(r io.Reader) (*bloomFilter, error) {
	header := make([]byte, 8)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	m := int(binary.LittleEndian.Uint32(header[0:4]))
	k := int(binary.LittleEndian.Uint32(header[4:8]))
	bitset := make([]byte, (m+7)/8)
	if _, err := io.ReadFull(r, bitset); err != nil {
		return nil, err
	}

	return &bloomFilter{m: m, k: k, bitset: bitset}, nil
}

func DefaultFilterPath() string {
	if p := os.Getenv("SAI_FILTER_PATH"); p != "" {
		return p
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "sai", "filters.bin")
}

func FilterFileExists() bool {
	_, err := os.Stat(DefaultFilterPath())
	return err == nil
}

type FilterSetData struct {
	Agents         []FilterAgent `json:"agents"`
	IgnoredDomains []string      `json:"ignored_domains"`
}

func (f *FilterSet) Export() FilterSetData {
	f.mu.RLock()
	defer f.mu.RUnlock()

	agents := make([]FilterAgent, len(f.agents))
	copy(agents, f.agents)

	ignored := make([]string, len(f.ignoredDomains))
	copy(ignored, f.ignoredDomains)

	return FilterSetData{
		Agents:         agents,
		IgnoredDomains: ignored,
	}
}

func (f *FilterSet) Import(data FilterSetData) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.agents = make([]FilterAgent, len(data.Agents))
	copy(f.agents, data.Agents)

	f.ignoredDomains = make([]string, len(data.IgnoredDomains))
	copy(f.ignoredDomains, data.IgnoredDomains)

	f.nonAIFilter = newBloomFilter(10000, 0.01)
	for _, d := range f.ignoredDomains {
		f.nonAIFilter.Add(d)
	}
}
