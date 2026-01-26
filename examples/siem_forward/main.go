// SIEM forwarding example.
// Shows how to forward sai events to Graylog, Splunk, or other SIEMs.
// Outputs GELF (Graylog Extended Log Format) to stdout - adapt for your SIEM.
//
// Testing with Graylog:
//
//	1. Start Graylog:
//	     cd examples/siem_forward
//	     docker compose up -d
//
//	2. Wait ~60s for startup, then create the GELF HTTP input:
//	     curl -u admin:admin -X POST http://localhost:9000/api/system/inputs -H "Content-Type: application/json" -H "X-Requested-By: cli" -d '{"title":"GELF HTTP","type":"org.graylog2.inputs.gelf.http.GELFHttpInput","global":true,"configuration":{"bind_address":"0.0.0.0","port":12202}}'
//
//	3. Run the example (from repo root):
//	     GRAYLOG_URL=http://localhost:12202/gelf go run ./examples/siem_forward
//
//	4. Generate AI traffic and check Graylog:
//	     Open http://localhost:9000 (admin/admin) > Search
//
//	5. Cleanup:
//	     cd examples/siem_forward && docker compose down -v
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"

	"github.com/knostic/sai"
)

// GELF message format for Graylog
type GELFMessage struct {
	Version      string  `json:"version"`
	Host         string  `json:"host"`
	ShortMessage string  `json:"short_message"`
	Timestamp    float64 `json:"timestamp"`
	Level        int     `json:"level"` // 6 = info

	Process   string  `json:"_process"`
	Domain    string  `json:"_domain"`
	PID       int     `json:"_pid"`
	Agent     string  `json:"_agent,omitempty"`
	AIScore   float64 `json:"_ai_score"`
	Source    string  `json:"_source"`
	Facility  string  `json:"_facility"`
}

func main() {
	// For real usage: graylogURL := "http://graylog.example.com:12202/gelf"
	graylogURL := os.Getenv("GRAYLOG_URL") // e.g. "http://localhost:12202/gelf"

	if graylogURL != "" {
		log.Printf("forwarding to graylog at %s", graylogURL)
	} else {
		log.Println("GRAYLOG_URL not set, printing to stdout")
	}

	hostname, _ := os.Hostname()

	fs := sai.NewOverrides()
	fs.AddAgent("claude", "claude*", []string{"*.anthropic.com"})
	fs.AddAgent("cursor", "cursor*", []string{"*.anthropic.com", "*.openai.com"})

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

	for {
		select {
		case event := <-mon.Events():
			acc.Record(event)
			event.Agent = fs.MatchAgent(event.Process, event.Domain)
			event.AIScore = acc.AIScore(event.Process, event.Domain)

			if event.Agent == "" && event.AIScore < 0.3 {
				continue
			}

			msg := toGELF(event, hostname)
			data, _ := json.Marshal(msg)

			if graylogURL != "" {
				resp, err := http.Post(graylogURL, "application/json", bytes.NewReader(data))
				if err != nil {
					log.Printf("failed to send to graylog: %v", err)
					continue
				}
				resp.Body.Close()
			} else {
				fmt.Println(string(data))
			}

		case <-sig:
			return
		}
	}
}

func toGELF(e sai.Event, hostname string) GELFMessage {
	short := fmt.Sprintf("AI traffic: %s -> %s", e.Process, e.Domain)
	if e.Agent != "" {
		short = fmt.Sprintf("AI agent %s: %s -> %s", e.Agent, e.Process, e.Domain)
	}

	return GELFMessage{
		Version:      "1.1",
		Host:         hostname,
		ShortMessage: short,
		Timestamp:    float64(e.Timestamp.UnixNano()) / 1e9,
		Level:        6,
		Process:      e.Process,
		Domain:       e.Domain,
		PID:          e.PID,
		Agent:        e.Agent,
		AIScore:      float64(e.AIScore),
		Source:       e.Source,
		Facility:     "sai",
	}
}

// Splunk HEC example (commented out):
//
// func sendToSplunk(event sai.Event, hecURL, hecToken string) error {
//     payload := map[string]any{
//         "event":      event,
//         "sourcetype": "sai:shadow_ai",
//         "source":     "sai",
//     }
//     data, _ := json.Marshal(payload)
//     req, _ := http.NewRequest("POST", hecURL, bytes.NewReader(data))
//     req.Header.Set("Authorization", "Splunk "+hecToken)
//     resp, err := http.DefaultClient.Do(req)
//     if err != nil {
//         return err
//     }
//     resp.Body.Close()
//     return nil
// }

// Elastic example (commented out):
//
// func sendToElastic(event sai.Event, esURL string) error {
//     data, _ := json.Marshal(event)
//     resp, err := http.Post(esURL+"/sai-events/_doc", "application/json", bytes.NewReader(data))
//     if err != nil {
//         return err
//     }
//     resp.Body.Close()
//     return nil
// }
