// Full monitoring example with accumulator.
// Tracks events, computes confidence, and identifies AI agents.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/knostic/sai"
)

func main() {
	fs := sai.NewOverrides()
	fs.AddAgent("claude", "claude*", []string{"*.anthropic.com"})
	fs.AddAgent("openai", "python*", []string{"*.openai.com"})
	fs.AddAgent("cursor", "cursor*", []string{"*.anthropic.com", "*.openai.com"})
	fs.AddNoise("google.com")
	fs.AddNoise("apple.com")
	fs.AddNoise("cloudflare.com")

	registry := sai.NewClassifierRegistry()
	registry.Add(sai.NewDefaultClassifier())

	acc := sai.NewAccumulatorWithSignals(fs, registry)

	mon := sai.NewMonitor(sai.Config{Interface: "en0"})
	if err := mon.Start(); err != nil {
		log.Fatal(err)
	}
	defer mon.Stop()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	fmt.Println("Monitoring (Ctrl+C to stop)...")

	for {
		select {
		case event := <-mon.Events():
			acc.Record(event)

			event.Agent = fs.MatchAgent(event.Process, event.Domain)
			event.Confidence = acc.Confidence(event.Process, event.Domain)

			if event.Agent != "" || event.Confidence > 0.3 {
				out, _ := json.Marshal(event)
				fmt.Println(string(out))
			}

		case <-sig:
			fmt.Println("\nStopping...")
			return
		}
	}
}
