// Custom Classifier example.
// Shows how to load and use an external classifier with sai.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/knostic/sai"
)

func main() {
	dir, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	configPath := filepath.Join(dir, "classifier.json")
	classifier, err := sai.LoadProcessClassifier(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading classifier: %v\n", err)
		os.Exit(1)
	}
	defer classifier.Close()

	registry := sai.NewClassifierRegistry()
	registry.Add(classifier)

	acc := sai.NewAccumulatorWithSignals(sai.NewOverrides(), registry)

	events := []sai.Event{
		{Process: "curl", Domain: "api.openai.com", Source: "tls"},
		{Process: "python", Domain: "api.anthropic.com", Source: "tls"},
		{Process: "node", Domain: "api.example.com", Source: "tls"},
		{Process: "app", Domain: "my-ai-service.io", Source: "tls"},
	}

	for _, event := range events {
		acc.Record(event)
		conf := acc.Confidence(event.Process, event.Domain)
		fmt.Printf("%s -> %s  confidence=%.2f\n", event.Process, event.Domain, conf)
	}
}
