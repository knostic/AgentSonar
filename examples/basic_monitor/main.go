//go:build darwin

// Basic network monitoring example (darwin only).
// Prints all AI-related network events to stdout.
package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/knostic/sai"
)

func main() {
	mon := sai.NewMonitor(sai.Config{Interface: "en0"})

	if err := mon.Start(); err != nil {
		log.Fatal(err)
	}
	defer mon.Stop()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	fmt.Println("Monitoring network traffic (Ctrl+C to stop)...")

	for {
		select {
		case event := <-mon.Events():
			fmt.Printf("%s (%d) -> %s [%s]\n",
				event.Process, event.PID, event.Domain, event.Source)
		case <-sig:
			fmt.Println("\nStopping...")
			return
		}
	}
}
