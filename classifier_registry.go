// TODO: load classifiers from github repo

package sai

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"
)

type ClassifierInput struct {
	Domain  string     `json:"domain"`
	Process string     `json:"process"`
	Source  string     `json:"source"`
	JA4     string     `json:"ja4,omitempty"`
	Stats   *PairStats `json:"stats,omitempty"`
}

type ClassifierOutput struct {
	Confidence Confidence `json:"confidence"`
}

type Classifier interface {
	Name() string
	Classify(input ClassifierInput) (Confidence, error)
	Close() error
}

type ClassifierRegistry struct {
	classifiers []Classifier
	mu          sync.RWMutex
}

func NewClassifierRegistry() *ClassifierRegistry {
	return &ClassifierRegistry{}
}

func (r *ClassifierRegistry) Add(c Classifier) {
	r.mu.Lock()
	r.classifiers = append(r.classifiers, c)
	r.mu.Unlock()
}

func (r *ClassifierRegistry) Remove(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, c := range r.classifiers {
		if c.Name() == name {
			c.Close()
			r.classifiers = append(r.classifiers[:i], r.classifiers[i+1:]...)
			return
		}
	}
}

func (r *ClassifierRegistry) Classify(input ClassifierInput) Confidence {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var total Confidence
	for _, c := range r.classifiers {
		conf, err := c.Classify(input)
		if err == nil && conf > total {
			total = conf
		}
	}
	return total
}

func (r *ClassifierRegistry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, len(r.classifiers))
	for i, c := range r.classifiers {
		names[i] = c.Name()
	}
	return names
}

func (r *ClassifierRegistry) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.classifiers {
		c.Close()
	}
	r.classifiers = nil
}

type ProcessClassifier struct {
	name    string
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	stdout  *bufio.Scanner
	mu      sync.Mutex
	timeout time.Duration
}

type ProcessClassifierConfig struct {
	Name    string   `json:"name"`
	Command string   `json:"command"`
	Args    []string `json:"args,omitempty"`
	Timeout int      `json:"timeout_ms,omitempty"`
}

func NewProcessClassifier(cfg ProcessClassifierConfig) (*ProcessClassifier, error) {
	cmd := exec.Command(cfg.Command, cfg.Args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		stdin.Close()
		return nil, err
	}
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		stdin.Close()
		stdout.Close()
		return nil, err
	}

	timeout := 5 * time.Second
	if cfg.Timeout > 0 {
		timeout = time.Duration(cfg.Timeout) * time.Millisecond
	}

	return &ProcessClassifier{
		name:    cfg.Name,
		cmd:     cmd,
		stdin:   stdin,
		stdout:  bufio.NewScanner(stdout),
		timeout: timeout,
	}, nil
}

func (p *ProcessClassifier) Name() string {
	return p.name
}

func (p *ProcessClassifier) Classify(input ClassifierInput) (Confidence, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	data, err := json.Marshal(input)
	if err != nil {
		return 0, err
	}
	data = append(data, '\n')

	if _, err := p.stdin.Write(data); err != nil {
		return 0, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()

	done := make(chan struct{})
	var output ClassifierOutput
	var scanErr error

	go func() {
		if p.stdout.Scan() {
			scanErr = json.Unmarshal(p.stdout.Bytes(), &output)
		} else {
			scanErr = p.stdout.Err()
		}
		close(done)
	}()

	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-done:
		if scanErr != nil {
			return 0, scanErr
		}
		return output.Confidence, nil
	}
}

func (p *ProcessClassifier) Close() error {
	p.stdin.Close()
	return p.cmd.Process.Kill()
}

func LoadProcessClassifier(path string) (*ProcessClassifier, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg ProcessClassifierConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return NewProcessClassifier(cfg)
}
