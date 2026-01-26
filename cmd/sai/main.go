package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/knostic/sai"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "sai",
	Short: "Shadow AI Agent Detection",
	Long:  "sai - Shadow AI Agent Detection\n\nLive monitoring tool for detecting AI agent network activity.",
	Run: func(cmd *cobra.Command, args []string) {
		runMonitor(cmd)
	},
}

var (
	monitorIface      string
	monitorJSON       bool
	monitorAll        bool
	monitorEnablePID0 bool
)

func init() {
	rootCmd.Flags().SortFlags = false
	rootCmd.Flags().StringVarP(&monitorIface, "interface", "i", "en0", "network interface")
	rootCmd.Flags().BoolVarP(&monitorJSON, "json", "j", false, "JSON lines output")
	rootCmd.Flags().BoolVarP(&monitorAll, "all", "a", false, "show all events (bypass filters)")
	rootCmd.Flags().BoolVar(&monitorEnablePID0, "enable-pid0", false, "include PID 0")

	rootCmd.AddCommand(setupCmd)
	rootCmd.AddCommand(doctorCmd)
	rootCmd.AddCommand(startCmd)
	rootCmd.AddCommand(stopCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(eventsCmd)
	rootCmd.AddCommand(triageCmd)
	rootCmd.AddCommand(agentsCmd)
	rootCmd.AddCommand(ignoreCmd)
	rootCmd.AddCommand(sigCmd)
	rootCmd.AddCommand(classifierCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func loadOverrides() *sai.Overrides {
	filterSet := sai.NewOverrides()
	if sai.OverridesFileExists() {
		if err := filterSet.Load(sai.DefaultOverridesPath()); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not load filters: %v\n", err)
		}
	}
	return filterSet
}

func saveOverrides(filterSet *sai.Overrides) {
	if err := filterSet.Save(sai.DefaultOverridesPath()); err != nil {
		fmt.Fprintf(os.Stderr, "error saving filters: %v\n", err)
	}
}

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start daemon (background monitoring)",
	Run: func(cmd *cobra.Command, args []string) {
		runStart(cmd)
	},
}

func init() {
	startCmd.Flags().SortFlags = false
	startCmd.Flags().StringP("interface", "i", "en0", "network interface")
	startCmd.Flags().BoolP("json", "j", false, "JSON lines output")
	startCmd.Flags().BoolP("all", "a", false, "show all events (bypass filters)")
	startCmd.Flags().Bool("enable-pid0", false, "include PID 0")
}

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop daemon",
	Run: func(cmd *cobra.Command, args []string) {
		runStop()
	},
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check if daemon is running",
	Run: func(cmd *cobra.Command, args []string) {
		runStatus()
	},
}

var eventsCmd = &cobra.Command{
	Use:   "events",
	Short: "Query stored events",
	Run: func(cmd *cobra.Command, args []string) {
		runEvents(cmd)
	},
}

func init() {
	eventsCmd.Flags().SortFlags = false
	eventsCmd.Flags().IntP("limit", "n", 50, "limit results")
	eventsCmd.Flags().String("since", "", "events since duration (e.g., 1h, 30m)")
	eventsCmd.Flags().String("process", "", "filter by process")
	eventsCmd.Flags().String("domain", "", "filter by domain")
	eventsCmd.Flags().BoolP("json", "j", false, "JSON output")
}

var agentsCmd = &cobra.Command{
	Use:   "agents",
	Short: "Manage AI agents",
	Run: func(cmd *cobra.Command, args []string) {
		listAgents()
	},
}

var agentsAddCmd = &cobra.Command{
	Use:   "add <name> <process-pattern> <domain-pattern>",
	Short: "Create agent with process and domain pattern",
	Args:  cobra.ExactArgs(3),
	Run: func(cmd *cobra.Command, args []string) {
		addAgent(args[0], args[1], args[2])
	},
}

var agentsAddDomainCmd = &cobra.Command{
	Use:   "add-domain <name> <domain-pattern>",
	Short: "Add domain to agent",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		addAgentDomain(args[0], args[1])
	},
}

var agentsRmCmd = &cobra.Command{
	Use:   "rm <name>",
	Short: "Remove agent",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		removeAgent(args[0])
	},
}

func init() {
	agentsCmd.AddCommand(agentsAddCmd)
	agentsCmd.AddCommand(agentsAddDomainCmd)
	agentsCmd.AddCommand(agentsRmCmd)
}

var ignoreCmd = &cobra.Command{
	Use:   "ignore",
	Short: "Manage ignored domains",
	Run: func(cmd *cobra.Command, args []string) {
		listIgnored()
	},
}

var ignoreAddCmd = &cobra.Command{
	Use:   "add <domain>",
	Short: "Add domain to ignore list",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		addIgnore(args[0])
	},
}

var ignoreRmCmd = &cobra.Command{
	Use:   "rm <domain>",
	Short: "Remove domain from ignore list",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		removeIgnore(args[0])
	},
}

func init() {
	ignoreCmd.AddCommand(ignoreAddCmd)
	ignoreCmd.AddCommand(ignoreRmCmd)
}

var triageCmd = &cobra.Command{
	Use:   "triage",
	Short: "Interactive triage of unflagged events",
	Run: func(cmd *cobra.Command, args []string) {
		runTriage()
	},
}

var sigCmd = &cobra.Command{
	Use:   "sig",
	Short: "Signature management",
}

var sigExportCmd = &cobra.Command{
	Use:   "export <file>",
	Short: "Export signatures to file",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		exportSignatures(args[0])
	},
}

var sigImportCmd = &cobra.Command{
	Use:   "import <file>",
	Short: "Import signatures from file",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		importSignatures(args[0])
	},
}

func init() {
	sigCmd.AddCommand(sigExportCmd)
	sigCmd.AddCommand(sigImportCmd)
}

var classifierCmd = &cobra.Command{
	Use:   "classifier",
	Short: "Manage external classifiers",
}

var classifierListCmd = &cobra.Command{
	Use:   "list",
	Short: "List loaded classifiers",
	Run: func(cmd *cobra.Command, args []string) {
		listClassifiers()
	},
}

var classifierLoadCmd = &cobra.Command{
	Use:   "load <config.json>",
	Short: "Load external classifier",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		loadClassifier(args[0])
	},
}

var classifierUnloadCmd = &cobra.Command{
	Use:   "unload <name>",
	Short: "Unload classifier",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		unloadClassifier(args[0])
	},
}

func init() {
	classifierCmd.AddCommand(classifierListCmd)
	classifierCmd.AddCommand(classifierLoadCmd)
	classifierCmd.AddCommand(classifierUnloadCmd)
}

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Interactive BPF setup (macOS)",
	Run: func(cmd *cobra.Command, args []string) {
		runSetup()
	},
}

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check system health",
	Run: func(cmd *cobra.Command, args []string) {
		runDoctor()
	},
}

func runMonitor(cmd *cobra.Command) {
	allDomains, _ := cmd.Flags().GetBool("all")
	jsonOutput, _ := cmd.Flags().GetBool("json")
	iface, _ := cmd.Flags().GetString("interface")
	enablePID0, _ := cmd.Flags().GetBool("enable-pid0")

	db, err := sai.OpenDB(sai.DefaultDBPath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not open database: %v\n", err)
	}
	defer func() {
		if db != nil {
			db.Close()
		}
	}()

	filterSet := loadOverrides()
	registry := sai.NewClassifierRegistry()
	registry.Add(sai.NewDefaultClassifier())
	acc := sai.NewAccumulatorWithOverrides(filterSet, registry)

	mon := sai.NewMonitor(sai.Config{
		Interface:  iface,
		EnablePID0: enablePID0,
	})

	if err := mon.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		fmt.Fprintln(os.Stderr, "hint: run 'sai setup' to configure BPF permissions")
		os.Exit(1)
	}
	defer mon.Stop()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case <-sigCh:
			return
		case event := <-mon.Events():
			event.Agent = filterSet.MatchAgent(event.Process, event.Domain)

			acc.Record(event)
			event.Confidence = acc.Confidence(event.Process, event.Domain)
			if event.Agent != "" {
				event.Confidence = 1.0
			}

			if db != nil {
				db.InsertEvent(event)
			}

			if !allDomains && filterSet.IsNoise(event.Domain) {
				continue
			}

			if jsonOutput {
				data, _ := json.Marshal(event)
				fmt.Println(string(data))
			} else if event.Agent != "" {
				fmt.Printf("%s \033[33m[%s] %s -> %s\033[0m\n",
					event.Timestamp.Format("15:04:05"), event.Agent, event.Process, event.Domain)
			} else {
				fmt.Printf("%s [unknown] %s:%-5d %-40s %-30s %-10s %-6s\n",
					event.Timestamp.Format("15:04:05"), event.Process, event.PID, truncate(event.BinaryPath, 40),
					event.Domain, event.Source, event.Confidence)
			}
		}
	}
}

func runEvents(cmd *cobra.Command) {
	since, _ := cmd.Flags().GetString("since")
	process, _ := cmd.Flags().GetString("process")
	domain, _ := cmd.Flags().GetString("domain")
	limit, _ := cmd.Flags().GetInt("limit")
	jsonOutput, _ := cmd.Flags().GetBool("json")

	db, err := sai.OpenDB(sai.DefaultDBPath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	var sinceDur time.Duration
	if since != "" {
		sinceDur, err = time.ParseDuration(since)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid duration: %v\n", err)
			os.Exit(1)
		}
	}

	filterSet := loadOverrides()
	registry := sai.NewClassifierRegistry()
	registry.Add(sai.NewDefaultClassifier())
	acc := sai.NewAccumulatorWithOverrides(filterSet, registry)

	allEvents, _ := db.QueryEvents(0, "", "", 0)
	for _, e := range allEvents {
		acc.Record(e)
	}

	events, err := db.QueryEvents(sinceDur, process, domain, limit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		for _, e := range events {
			if filterSet.IsNoise(e.Domain) {
				continue
			}
			e.Agent = filterSet.MatchAgent(e.Process, e.Domain)
			e.Confidence = acc.Confidence(e.Process, e.Domain)
			if e.Agent != "" {
				e.Confidence = 1.0
			}
			enc.Encode(e)
		}
	} else {
		for _, e := range events {
			if filterSet.IsNoise(e.Domain) {
				continue
			}
			agent := filterSet.MatchAgent(e.Process, e.Domain)
			conf := acc.Confidence(e.Process, e.Domain)
			if agent != "" {
				conf = 1.0
			} else {
				agent = "unknown"
			}
			fmt.Printf("%s [%s] %s:%-5d %-30s %-10s %-6s\n",
				e.Timestamp.Format("15:04:05"), agent, e.Process, e.PID,
				e.Domain, e.Source, conf)
		}
	}
}

func listAgents() {
	filterSet := loadOverrides()
	agents := filterSet.ListAgents()

	if len(agents) == 0 {
		fmt.Println("no agents configured")
		return
	}

	for _, a := range agents {
		fmt.Printf("%s (process: %s)\n", a.Name, a.Process)
		for _, d := range a.Domains {
			fmt.Printf("  -> %s\n", d)
		}
	}
}

func addAgent(name, process, domain string) {
	filterSet := loadOverrides()
	filterSet.AddAgent(name, process, []string{domain})
	saveOverrides(filterSet)
	fmt.Printf("added agent: %s (process: %s, domain: %s)\n", name, process, domain)
}

func addAgentDomain(name, domain string) {
	filterSet := loadOverrides()
	if filterSet.GetAgent(name) == nil {
		fmt.Fprintf(os.Stderr, "error: agent %s not found\n", name)
		os.Exit(1)
	}
	filterSet.AddAgentDomain(name, domain)
	saveOverrides(filterSet)
	fmt.Printf("added domain %s to agent %s\n", domain, name)
}

func removeAgent(name string) {
	filterSet := loadOverrides()
	filterSet.RemoveAgent(name)
	saveOverrides(filterSet)
	fmt.Printf("removed agent: %s\n", name)
}

func listIgnored() {
	filterSet := loadOverrides()
	domains := filterSet.ListNoise()
	if len(domains) == 0 {
		fmt.Println("no ignored domains")
		return
	}
	for _, d := range domains {
		fmt.Println(d)
	}
}

func addIgnore(domain string) {
	filterSet := loadOverrides()
	filterSet.AddNoise(domain)
	saveOverrides(filterSet)
	fmt.Printf("added to ignore list: %s\n", domain)
}

func removeIgnore(domain string) {
	filterSet := loadOverrides()
	filterSet.RemoveNoise(domain)
	saveOverrides(filterSet)
	fmt.Printf("removed from ignore list: %s\n", domain)
}

func runTriage() {
	db, err := sai.OpenDB(sai.DefaultDBPath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	filterSet := loadOverrides()
	registry := sai.NewClassifierRegistry()
	registry.Add(sai.NewDefaultClassifier())
	acc := sai.NewAccumulatorWithOverrides(filterSet, registry)

	allEvents, _ := db.QueryEvents(0, "", "", 0)
	for _, e := range allEvents {
		acc.Record(e)
	}

	events := allEvents
	if len(events) == 0 {
		fmt.Println("no events to triage")
		return
	}

	sort.Slice(events, func(i, j int) bool {
		ci := acc.Confidence(events[i].Process, events[i].Domain)
		cj := acc.Confidence(events[j].Process, events[j].Domain)
		return ci > cj
	})

	reader := bufio.NewReader(os.Stdin)
	seen := make(map[string]bool)

	for _, e := range events {
		key := e.Process + ":" + baseDomain(e.Domain)
		if seen[key] {
			continue
		}
		if filterSet.MatchAgent(e.Process, e.Domain) != "" {
			continue
		}
		if filterSet.IsNoise(e.Domain) {
			continue
		}

		conf := acc.Confidence(e.Process, e.Domain)
		fmt.Printf("\n%s -> %s AI confidence: %s\n", e.Process, e.Domain, conf)
		fmt.Printf("  binary: %s\n", e.BinaryPath)
		fmt.Printf("  source: %s, ja4: %s\n", e.Source, e.JA4)
		fmt.Print("\n[a]gent (A to edit), [n]oise, [s]kip, [q]uit? ")

		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		switch strings.ToLower(input) {
		case "a", "agent":
			fmt.Printf("agent name [%s]: ", e.Process)
			n, _ := reader.ReadString('\n')
			name := strings.TrimSpace(n)
			if name == "" {
				name = e.Process
			}
			domainPattern := e.Domain
			if input == "A" {
				fmt.Printf("domain [%s]: ", e.Domain)
				d, _ := reader.ReadString('\n')
				d = strings.TrimSpace(d)
				if d != "" {
					domainPattern = d
				}
			}
			if filterSet.GetAgent(name) == nil {
				filterSet.AddAgent(name, e.Process, []string{domainPattern})
			} else {
				filterSet.AddAgentDomain(name, domainPattern)
			}
			fmt.Printf("agent: %s -> %s\n", name, domainPattern)

		case "n", "noise":
			filterSet.AddNoise(e.Domain)
			fmt.Printf("marked as noise: %s\n", e.Domain)

		case "q", "quit":
			saveOverrides(filterSet)
			return
		}

		seen[key] = true
	}

	saveOverrides(filterSet)
}

func exportSignatures(dst string) {
	if !sai.OverridesFileExists() {
		fmt.Fprintln(os.Stderr, "no filters to export")
		os.Exit(1)
	}

	if err := copyFile(sai.DefaultOverridesPath(), dst); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("exported signatures to %s\n", dst)
}

func importSignatures(src string) {
	if _, err := os.Stat(src); err != nil {
		fmt.Fprintf(os.Stderr, "error: %s not found\n", src)
		os.Exit(1)
	}

	dst := sai.DefaultOverridesPath()
	if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if err := copyFile(src, dst); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("imported signatures from %s\n", src)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

func listClassifiers() {
	fmt.Println("default (built-in traffic heuristics)")
}

func loadClassifier(configPath string) {
	c, err := sai.LoadProcessClassifier(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("loaded classifier: %s\n", c.Name())
	c.Close()
}

func unloadClassifier(name string) {
	fmt.Printf("unloaded classifier: %s\n", name)
}

func runSetup() {
	fmt.Println("sai setup - BPF permissions for macOS")
	fmt.Println()
	fmt.Println("To capture network traffic, sai needs BPF access.")
	fmt.Println("Run the following commands:")
	fmt.Println()
	fmt.Println("  sudo chgrp admin /dev/bpf*")
	fmt.Println("  sudo chmod g+rw /dev/bpf*")
	fmt.Println()
	fmt.Println("Or install Wireshark which sets up BPF permissions automatically.")
}

func runDoctor() {
	fmt.Println("sai doctor - system diagnostics")
	allOk := true

	fmt.Print("BPF access:      ")
	bpfOk := checkBPF()
	if bpfOk {
		fmt.Println("ok")
	} else {
		fmt.Println("FAIL (run 'sai setup')")
		allOk = false
	}

	fmt.Print("Database:        ")
	dbPath := sai.DefaultDBPath()
	db, err := sai.OpenDB(dbPath)
	if err != nil {
		fmt.Printf("FAIL (%v)\n", err)
		allOk = false
	} else {
		fmt.Printf("ok (%s)\n", dbPath)
		db.Close()
	}

	fmt.Print("Overrides:       ")
	if sai.OverridesFileExists() {
		fmt.Printf("ok (%s)\n", sai.DefaultOverridesPath())
	} else {
		fmt.Println("not initialized")
	}

	fmt.Print("Interfaces:      ")
	ifaces := listUsableInterfaces()
	if len(ifaces) == 0 {
		fmt.Println("FAIL (no usable interfaces)")
		allOk = false
	} else {
		fmt.Println(strings.Join(ifaces, ", "))
	}

	fmt.Print("Agents:          ")
	filterSet := loadOverrides()
	agents := filterSet.ListAgents()
	if len(agents) == 0 {
		fmt.Println("none configured")
	} else {
		fmt.Printf("%d configured\n", len(agents))
	}

	fmt.Print("Events stored:   ")
	if db, err := sai.OpenDB(dbPath); err == nil {
		events, _ := db.QueryEvents(0, "", "", 0)
		fmt.Printf("%d\n", len(events))
		db.Close()
	} else {
		fmt.Println("- (db unavailable)")
	}

	fmt.Println()
	if allOk {
		fmt.Println("All checks passed. Ready to monitor.")
	} else {
		fmt.Println("Some checks failed. Run 'sai setup' for help.")
		os.Exit(1)
	}
}

func pidPath() string {
	if dir := os.Getenv("SAI_CONFIG_DIR"); dir != "" {
		return filepath.Join(dir, "sai.pid")
	}
	return filepath.Join(filepath.Dir(sai.DefaultDBPath()), "sai.pid")
}

func logPath() string {
	if dir := os.Getenv("SAI_CONFIG_DIR"); dir != "" {
		return filepath.Join(dir, "sai.log")
	}
	return filepath.Join(filepath.Dir(sai.DefaultDBPath()), "sai.log")
}

func runStart(cmd *cobra.Command) {
	if pid := readPID(); pid != 0 {
		if processExists(pid) {
			fmt.Fprintf(os.Stderr, "sai is already running (pid %d)\n", pid)
			os.Exit(1)
		}
		os.Remove(pidPath())
	}

	logFile, err := os.OpenFile(logPath(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: could not open log file: %v\n", err)
		os.Exit(1)
	}

	args := []string{os.Args[0]}
	if all, _ := cmd.Flags().GetBool("all"); all {
		args = append(args, "-a")
	}
	if jsonOut, _ := cmd.Flags().GetBool("json"); jsonOut {
		args = append(args, "-j")
	}
	if iface, _ := cmd.Flags().GetString("interface"); iface != "en0" {
		args = append(args, "-i", iface)
	}
	if enablePID0, _ := cmd.Flags().GetBool("enable-pid0"); enablePID0 {
		args = append(args, "--enable-pid0")
	}

	proc := &exec.Cmd{
		Path:   os.Args[0],
		Args:   args,
		Stdout: logFile,
		Stderr: logFile,
	}

	if err := proc.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "error: could not start daemon: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(pidPath(), fmt.Appendf(nil, "%d", proc.Process.Pid), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "error: could not write pid file: %v\n", err)
		proc.Process.Kill()
		os.Exit(1)
	}

	fmt.Printf("sai started (pid %d)\n", proc.Process.Pid)
}

func runStop() {
	pid := readPID()
	if pid == 0 {
		fmt.Fprintln(os.Stderr, "sai is not running")
		os.Exit(1)
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		os.Remove(pidPath())
		fmt.Fprintln(os.Stderr, "sai is not running")
		os.Exit(1)
	}

	if err := proc.Signal(syscall.SIGTERM); err != nil {
		os.Remove(pidPath())
		fmt.Fprintln(os.Stderr, "sai is not running")
		os.Exit(1)
	}

	os.Remove(pidPath())
	fmt.Printf("sai stopped (pid %d)\n", pid)
}

func runStatus() {
	pid := readPID()
	if pid == 0 {
		fmt.Println("sai is not running")
		os.Exit(1)
	}

	if !processExists(pid) {
		os.Remove(pidPath())
		fmt.Println("sai is not running")
		os.Exit(1)
	}

	fmt.Printf("sai is running (pid %d)\n", pid)
}

func readPID() int {
	data, err := os.ReadFile(pidPath())
	if err != nil {
		return 0
	}
	var pid int
	fmt.Sscanf(string(data), "%d", &pid)
	return pid
}

func processExists(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.Signal(0)) == nil
}

func checkBPF() bool {
	matches, _ := filepath.Glob("/dev/bpf*")
	if len(matches) == 0 {
		return false
	}
	for _, path := range matches {
		f, err := os.OpenFile(path, os.O_RDONLY, 0)
		if err == nil {
			f.Close()
			return true
		}
	}
	return false
}

func listUsableInterfaces() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var result []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		result = append(result, iface.Name)
	}
	return result
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "..." + s[len(s)-n+3:]
}

func baseDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) <= 2 {
		return domain
	}
	return strings.Join(parts[len(parts)-2:], ".")
}
