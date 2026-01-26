package sai

import (
	"crypto/rand"
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type SigmaRule struct {
	Title       string            `yaml:"title"`
	ID          string            `yaml:"id"`
	Status      string            `yaml:"status"`
	Description string            `yaml:"description,omitempty"`
	Author      string            `yaml:"author"`
	Date        string            `yaml:"date"`
	LogSource   SigmaLogSource    `yaml:"logsource"`
	Detection   SigmaDetection    `yaml:"detection"`
	Level       string            `yaml:"level"`
	Tags        []string          `yaml:"tags,omitempty"`
}

type SigmaLogSource struct {
	Category string `yaml:"category"`
	Product  string `yaml:"product"`
}

type SigmaDetection struct {
	Selection map[string]any `yaml:"selection,omitempty"`
	Filter    map[string]any `yaml:"filter,omitempty"`
	Condition string         `yaml:"condition"`
}

func AgentToSigma(agent Agent) SigmaRule {
	selection := make(map[string]any)

	if agent.Process != "" && agent.Process != "*" {
		key, val := patternToSigmaField("ProcessName", agent.Process)
		if val != nil {
			selection[key] = val
		}
	}

	if len(agent.Domains) > 0 {
		var vals []any
		for _, d := range agent.Domains {
			if d == "*" {
				continue
			}
			_, val := patternToSigmaField("", d)
			if val != nil {
				vals = append(vals, val)
			}
		}
		if len(vals) == 1 {
			key, _ := patternToSigmaField("DestinationHostname", agent.Domains[0])
			selection[key] = vals[0]
		} else if len(vals) > 1 {
			key := domainFieldKey(agent.Domains)
			selection[key] = vals
		}
	}

	date := agent.CreatedAt.Format("2006/01/02")
	if agent.CreatedAt.IsZero() {
		date = time.Now().UTC().Format("2006/01/02")
	}

	return SigmaRule{
		Title:       agent.Name,
		ID:          generateUUID(),
		Status:      "experimental",
		Description: fmt.Sprintf("Detects %s AI agent network activity", agent.Name),
		Author:      "sai",
		Date:        date,
		LogSource: SigmaLogSource{
			Category: "network_connection",
			Product:  "any",
		},
		Detection: SigmaDetection{
			Selection: selection,
			Condition: "selection",
		},
		Level: "informational",
		Tags:  []string{"attack.exfiltration", "knostic.shadow_ai"},
	}
}

func NoiseToSigmaFilter(domains []string) SigmaRule {
	if len(domains) == 0 {
		return SigmaRule{}
	}

	var vals []any
	for _, d := range domains {
		vals = append(vals, d)
	}

	filter := map[string]any{
		"DestinationHostname|endswith": vals,
	}

	return SigmaRule{
		Title:       "sai Noise Filter",
		ID:          generateUUID(),
		Status:      "experimental",
		Description: "Domains excluded from AI detection (known non-AI)",
		Author:      "sai",
		Date:        time.Now().UTC().Format("2006/01/02"),
		LogSource: SigmaLogSource{
			Category: "network_connection",
			Product:  "any",
		},
		Detection: SigmaDetection{
			Filter:    filter,
			Condition: "not filter",
		},
		Level: "informational",
	}
}

func SigmaToAgent(rule SigmaRule) (Agent, []string, error) {
	agent := Agent{
		Name:      rule.Title,
		CreatedAt: parseSigmaDate(rule.Date),
	}

	var noise []string

	if rule.Detection.Filter != nil {
		for key, val := range rule.Detection.Filter {
			domains := extractDomains(key, val)
			noise = append(noise, domains...)
		}
		return agent, noise, nil
	}

	for key, val := range rule.Detection.Selection {
		fieldName, modifier := parseSigmaFieldKey(key)

		switch fieldName {
		case "ProcessName":
			agent.Process = sigmaValueToPattern(modifier, val)
		case "DestinationHostname":
			domains := sigmaValuesToPatterns(modifier, val)
			agent.Domains = append(agent.Domains, domains...)
		}
	}

	if agent.Process == "" {
		agent.Process = "*"
	}

	return agent, nil, nil
}

func OverridesToSigmaYAML(data OverridesData) ([]byte, error) {
	var docs []string

	for _, agent := range data.Agents {
		rule := AgentToSigma(agent)
		b, err := yaml.Marshal(rule)
		if err != nil {
			return nil, err
		}
		docs = append(docs, string(b))
	}

	if len(data.Noise) > 0 {
		rule := NoiseToSigmaFilter(data.Noise)
		b, err := yaml.Marshal(rule)
		if err != nil {
			return nil, err
		}
		docs = append(docs, string(b))
	}

	return []byte(strings.Join(docs, "---\n")), nil
}

func SigmaYAMLToOverrides(data []byte) (OverridesData, error) {
	var result OverridesData

	docs := strings.Split(string(data), "---")
	for _, doc := range docs {
		doc = strings.TrimSpace(doc)
		if doc == "" {
			continue
		}

		var rule SigmaRule
		if err := yaml.Unmarshal([]byte(doc), &rule); err != nil {
			return result, err
		}

		agent, noise, err := SigmaToAgent(rule)
		if err != nil {
			return result, err
		}

		if len(noise) > 0 {
			result.Noise = append(result.Noise, noise...)
		} else if agent.Name != "" && (agent.Process != "" || len(agent.Domains) > 0) {
			result.Agents = append(result.Agents, agent)
		}
	}

	return result, nil
}

func patternToSigmaField(fieldBase, pattern string) (string, any) {
	if pattern == "*" {
		return fieldBase, nil
	}

	starPrefix := strings.HasPrefix(pattern, "*")
	starSuffix := strings.HasSuffix(pattern, "*")

	switch {
	case starPrefix && starSuffix:
		return fieldBase + "|contains", strings.Trim(pattern, "*")
	case strings.HasPrefix(pattern, "*."):
		return fieldBase + "|endswith", pattern[1:]
	case starPrefix:
		return fieldBase + "|endswith", strings.TrimPrefix(pattern, "*")
	case starSuffix:
		return fieldBase + "|startswith", strings.TrimSuffix(pattern, "*")
	default:
		return fieldBase, pattern
	}
}

func domainFieldKey(domains []string) string {
	allEndswith := true
	for _, d := range domains {
		if !strings.HasPrefix(d, "*.") && !strings.HasPrefix(d, "*") {
			allEndswith = false
			break
		}
	}
	if allEndswith {
		return "DestinationHostname|endswith"
	}
	return "DestinationHostname"
}

func parseSigmaFieldKey(key string) (string, string) {
	parts := strings.SplitN(key, "|", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return parts[0], ""
}

func sigmaValueToPattern(modifier string, val any) string {
	s := fmt.Sprintf("%v", val)
	switch modifier {
	case "startswith":
		return s + "*"
	case "endswith":
		if strings.HasPrefix(s, ".") {
			return "*" + s
		}
		return "*" + s
	case "contains":
		return "*" + s + "*"
	default:
		return s
	}
}

func sigmaValuesToPatterns(modifier string, val any) []string {
	switch v := val.(type) {
	case []any:
		var patterns []string
		for _, item := range v {
			patterns = append(patterns, sigmaValueToPattern(modifier, item))
		}
		return patterns
	default:
		return []string{sigmaValueToPattern(modifier, val)}
	}
}

func extractDomains(key string, val any) []string {
	var domains []string
	switch v := val.(type) {
	case []any:
		for _, item := range v {
			domains = append(domains, fmt.Sprintf("%v", item))
		}
	case string:
		domains = append(domains, v)
	}
	return domains
}

func parseSigmaDate(dateStr string) time.Time {
	formats := []string{"2006/01/02", "2006-01-02"}
	for _, f := range formats {
		if t, err := time.Parse(f, dateStr); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

func generateUUID() string {
	var uuid [16]byte
	rand.Read(uuid[:])
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	uuid[8] = (uuid[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16])
}
