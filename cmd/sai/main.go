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
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/knostic/sai"
	"github.com/spf13/cobra"
)

var isTTY = func() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}()

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

func defaultInterface() string {
	if runtime.GOOS == "darwin" {
		return "en0"
	}
	return "eth0"
}

func init() {
	rootCmd.Flags().SortFlags = false

	rootCmd.Flags().StringVarP(&monitorIface, "interface", "i", defaultInterface(), "network interface")
	rootCmd.Flags().BoolVarP(&monitorJSON, "json", "j", false, "JSON lines output")
	rootCmd.Flags().BoolVarP(&monitorAll, "all", "a", false, "show all events (bypass filters)")
	rootCmd.Flags().BoolVar(&monitorEnablePID0, "enable-pid0", false, "include PID 0")

	rootCmd.AddGroup(
		&cobra.Group{ID: "daemon", Title: "Daemon:"},
		&cobra.Group{ID: "query", Title: "Query:"},
		&cobra.Group{ID: "config", Title: "Configuration:"},
		&cobra.Group{ID: "system", Title: "System:"},
	)

	setupCmd.GroupID = "system"
	installCmd.GroupID = "system"
	uninstallCmd.GroupID = "system"
	doctorCmd.GroupID = "system"

	startCmd.GroupID = "daemon"
	stopCmd.GroupID = "daemon"
	statusCmd.GroupID = "daemon"

	eventsCmd.GroupID = "query"
	triageCmd.GroupID = "query"
	classifyCmd.GroupID = "query"

	agentsCmd.GroupID = "config"
	ignoreCmd.GroupID = "config"
	exportCmd.GroupID = "config"
	importCmd.GroupID = "config"
	classifierCmd.GroupID = "config"

	rootCmd.AddCommand(setupCmd)
	rootCmd.AddCommand(installCmd)
	rootCmd.AddCommand(uninstallCmd)
	rootCmd.AddCommand(doctorCmd)
	rootCmd.AddCommand(startCmd)
	rootCmd.AddCommand(stopCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(eventsCmd)
	rootCmd.AddCommand(triageCmd)
	rootCmd.AddCommand(agentsCmd)
	rootCmd.AddCommand(ignoreCmd)
	rootCmd.AddCommand(exportCmd)
	rootCmd.AddCommand(importCmd)
	rootCmd.AddCommand(classifierCmd)
	rootCmd.AddCommand(classifyCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func loadOverrides() *sai.Overrides {
	filterSet := sai.NewOverrides()
	path := sai.DefaultOverridesPath()
	if sai.OverridesFileExists() {
		if err := filterSet.Load(path); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not load filters: %v\n", err)
		}
	} else {
		filterSet.WatchPath(path)
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
	startCmd.Flags().StringP("interface", "i", defaultInterface(), "network interface")
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
	Use:     "agents",
	Aliases: []string{"agent"},
	Short:   "Manage AI agents",
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
	Use:   "add-domain <name> <domain-pattern>...",
	Short: "Add domains to agent (use - for stdin)",
	Args:  cobra.MinimumNArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		addAgentDomain(args[0], args[1:])
	},
}

var agentsRmCmd = &cobra.Command{
	Use:   "rm <name>...",
	Short: "Remove agents",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		for _, name := range args {
			removeAgent(name)
		}
	},
}

func init() {
	agentsCmd.AddCommand(agentsAddCmd)
	agentsCmd.AddCommand(agentsAddDomainCmd)
	agentsCmd.AddCommand(agentsRmCmd)
}

var ignoreCmd = &cobra.Command{
	Use:     "ignore",
	Aliases: []string{"ignores"},
	Short:   "Manage ignored domains",
	Run: func(cmd *cobra.Command, args []string) {
		listIgnored()
	},
}

var ignoreAddCmd = &cobra.Command{
	Use:   "add <domain>...",
	Short: "Add domains to ignore list (use - for stdin)",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		addIgnore(args)
	},
}

var ignoreRmCmd = &cobra.Command{
	Use:   "rm <domain>...",
	Short: "Remove domains from ignore list",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		for _, domain := range args {
			removeIgnore(domain)
		}
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

var exportCmd = &cobra.Command{
	Use:   "export <file>",
	Short: "Export signatures to file",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		format, _ := cmd.Flags().GetString("format")
		exportSignatures(args[0], format)
	},
}

var importCmd = &cobra.Command{
	Use:   "import <file>",
	Short: "Import signatures from file",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		format, _ := cmd.Flags().GetString("format")
		importSignatures(args[0], format)
	},
}

func init() {
	exportCmd.Flags().StringP("format", "f", "binary", "output format (binary, sigma)")
	importCmd.Flags().StringP("format", "f", "binary", "input format (binary, sigma)")
}

var classifierCmd = &cobra.Command{
	Use:     "classifier",
	Aliases: []string{"classifiers"},
	Short:   "Manage external classifiers",
	Run: func(cmd *cobra.Command, args []string) {
		listClassifiers()
	},
}

var classifyCmd = &cobra.Command{
	Use:   "classify",
	Short: "Classify events from stdin (JSON lines)",
	Long: `Classify events from stdin (JSON lines).

Example:
  echo '{"proc":"myagent","domain":"ai.example.com","source":"tls","extras":{"bytes_in":"50000","bytes_out":"1000","packets_in":"300","packets_out":"10","duration_ms":"10000","programmatic":"true"}}' | sai classify`,
	Run: func(cmd *cobra.Command, args []string) {
		classifiers, _ := cmd.Flags().GetStringSlice("classifier")
		runClassify(classifiers)
	},
}

func init() {
	classifyCmd.Flags().StringSliceP("classifier", "c", nil, "classifiers to use (default: all configured)")
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
	classifierCmd.AddCommand(classifierLoadCmd)
	classifierCmd.AddCommand(classifierUnloadCmd)
}

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Show BPF setup instructions (macOS)",
	Run: func(cmd *cobra.Command, args []string) {
		runSetup()
	},
}

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Setup permissions for packet capture",
	Run: func(cmd *cobra.Command, args []string) {
		runInstall()
	},
}

var uninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Remove capture permissions",
	Run: func(cmd *cobra.Command, args []string) {
		runUninstall()
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
	if runtime.GOOS == "darwin" && !userInGroup(os.Getenv("USER"), bpfGroup) {
		fmt.Fprintf(os.Stderr, "error: user not in %s group\n", bpfGroup)
		fmt.Fprintln(os.Stderr, "hint: run 'sai install' to configure BPF permissions")
		os.Exit(1)
	}

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
		fmt.Fprintln(os.Stderr, "hint: run 'sai install' to configure capture permissions")
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
			event.AIScore = acc.AIScore(event.Process, event.Domain)
			if event.Agent != "" {
				event.AIScore = 1.0
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
			} else {
				agent := event.Agent
				if agent == "" {
					agent = "unknown"
				}
				printEvent(event.Timestamp, agent, event.Process, event.PID, event.Domain, event.Source, event.AIScore)
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
			e.AIScore = acc.AIScore(e.Process, e.Domain)
			if e.Agent != "" {
				e.AIScore = 1.0
			}
			enc.Encode(e)
		}
	} else {
		for _, e := range events {
			if filterSet.IsNoise(e.Domain) {
				continue
			}
			agent := filterSet.MatchAgent(e.Process, e.Domain)
			conf := acc.AIScore(e.Process, e.Domain)
			if agent != "" {
				conf = 1.0
			} else {
				agent = "unknown"
			}
			printEvent(e.Timestamp, agent, e.Process, e.PID, e.Domain, e.Source, conf)
		}
	}
}

func runClassify(selectedClassifiers []string) {
	overrides := loadOverrides()
	registry := sai.NewClassifierRegistry()

	selected := make(map[string]bool)
	for _, name := range selectedClassifiers {
		selected[name] = true
	}
	useAll := len(selected) == 0

	if useAll || selected["default"] {
		registry.Add(sai.NewDefaultClassifier())
	}
	for _, cfg := range overrides.ListClassifiers() {
		if useAll || selected[cfg.Name] {
			c, err := sai.NewProcessClassifier(sai.ProcessClassifierConfig{
				Name:    cfg.Name,
				Command: cfg.Command,
				Args:    cfg.Args,
				Timeout: cfg.Timeout,
			})
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: could not load classifier %s: %v\n", cfg.Name, err)
				continue
			}
			registry.Add(c)
		}
	}
	defer registry.Close()

	acc := sai.NewAccumulatorWithOverrides(overrides, registry)

	scanner := bufio.NewScanner(os.Stdin)
	enc := json.NewEncoder(os.Stdout)

	for scanner.Scan() {
		var event sai.Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			continue
		}

		acc.Record(event)
		agent := overrides.MatchAgent(event.Process, event.Domain)
		isNoise := overrides.IsNoise(event.Domain)

		input := sai.ClassifierInput{
			Domain:  event.Domain,
			Process: event.Process,
			Source:  event.Source,
			JA4:     event.JA4,
			Stats:   acc.Stats(event.Process, event.Domain),
		}
		scores := registry.ClassifyAll(input)

		if agent != "" {
			scores["agent"] = 1.0
		}

		enc.Encode(map[string]any{
			"proc":     event.Process,
			"domain":   event.Domain,
			"scores":   scores,
			"agent":    agent,
			"is_noise": isNoise,
		})
	}
}

func listAgents() {
	filterSet := loadOverrides()
	agents := filterSet.ListAgents()

	if len(agents) == 0 {
		return
	}

	for _, a := range agents {
		createdAt := "-"
		if !a.CreatedAt.IsZero() {
			createdAt = a.CreatedAt.Local().Format(time.RFC3339)
		}
		fmt.Printf("%s\t%s\t%s\t%s\n", a.Name, a.Process, strings.Join(a.Domains, ","), createdAt)
	}
}

func addAgent(name, process, domain string) {
	filterSet := loadOverrides()
	filterSet.AddAgent(name, process, []string{domain})
	saveOverrides(filterSet)
}

func addAgentDomain(name string, domains []string) {
	filterSet := loadOverrides()
	if filterSet.GetAgent(name) == nil {
		fmt.Fprintf(os.Stderr, "error: agent %s not found\n", name)
		os.Exit(1)
	}
	if len(domains) == 1 && domains[0] == "-" {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			if d := strings.TrimSpace(scanner.Text()); d != "" {
				filterSet.AddAgentDomain(name, d)
			}
		}
	} else {
		for _, d := range domains {
			filterSet.AddAgentDomain(name, d)
		}
	}
	saveOverrides(filterSet)
}

func removeAgent(name string) {
	filterSet := loadOverrides()
	filterSet.RemoveAgent(name)
	saveOverrides(filterSet)
}

func listIgnored() {
	filterSet := loadOverrides()
	domains := filterSet.ListNoise()
	if len(domains) == 0 {
		return
	}
	for _, d := range domains {
		fmt.Println(d)
	}
}

func addIgnore(domains []string) {
	filterSet := loadOverrides()
	if len(domains) == 1 && domains[0] == "-" {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			if d := strings.TrimSpace(scanner.Text()); d != "" {
				filterSet.AddNoise(d)
			}
		}
	} else {
		for _, d := range domains {
			filterSet.AddNoise(d)
		}
	}
	saveOverrides(filterSet)
}

func removeIgnore(domain string) {
	filterSet := loadOverrides()
	filterSet.RemoveNoise(domain)
	saveOverrides(filterSet)
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
		ci := acc.AIScore(events[i].Process, events[i].Domain)
		cj := acc.AIScore(events[j].Process, events[j].Domain)
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

		score := acc.AIScore(e.Process, e.Domain)
		fmt.Printf("\n%s -> %s  AI score: %s\n", e.Process, e.Domain, score)
		fmt.Printf("  binary: %s\n", e.BinaryPath)
		fmt.Printf("  source: %s, ja4: %s\n", e.Source, e.JA4)
		scores := registry.ClassifyAll(sai.ClassifierInput{
			Domain:  e.Domain,
			Process: e.Process,
			Stats:   acc.Stats(e.Process, e.Domain),
		})
		if len(scores) > 0 {
			fmt.Print("  classifiers: ")
			first := true
			for name, s := range scores {
				if !first {
					fmt.Print(", ")
				}
				fmt.Printf("%s=%s", name, s)
				first = false
			}
			fmt.Println()
		}
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

func exportSignatures(dst, format string) {
	if !sai.OverridesFileExists() {
		fmt.Fprintln(os.Stderr, "no filters to export")
		os.Exit(1)
	}

	switch format {
	case "binary":
		if err := copyFile(sai.DefaultOverridesPath(), dst); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "sigma":
		filterSet := loadOverrides()
		data := filterSet.Export()
		yamlData, err := sai.OverridesToSigmaYAML(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		if err := os.WriteFile(dst, yamlData, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "error: unknown format %q (use binary or sigma)\n", format)
		os.Exit(1)
	}
}

func importSignatures(src, format string) {
	if _, err := os.Stat(src); err != nil {
		fmt.Fprintf(os.Stderr, "error: %s not found\n", src)
		os.Exit(1)
	}

	switch format {
	case "binary":
		dst := sai.DefaultOverridesPath()
		if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		if err := copyFile(src, dst); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "sigma":
		data, err := os.ReadFile(src)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		overridesData, err := sai.SigmaYAMLToOverrides(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error parsing sigma rules: %v\n", err)
			os.Exit(1)
		}
		filterSet := loadOverrides()
		for _, agent := range overridesData.Agents {
			filterSet.AddAgent(agent.Name, agent.Process, agent.Domains)
		}
		for _, domain := range overridesData.Noise {
			filterSet.AddNoise(domain)
		}
		saveOverrides(filterSet)
	default:
		fmt.Fprintf(os.Stderr, "error: unknown format %q (use binary or sigma)\n", format)
		os.Exit(1)
	}
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
	fmt.Printf("%s\t%s\n", "default", "(built-in)")
	overrides := loadOverrides()
	for _, c := range overrides.ListClassifiers() {
		fmt.Printf("%s\t%s\n", c.Name, c.Command)
	}
}

func loadClassifier(configPath string) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	var cfg sai.ClassifierConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	overrides := loadOverrides()
	overrides.AddClassifier(cfg)
	saveOverrides(overrides)
	fmt.Printf("loaded classifier: %s\n", cfg.Name)
}

func unloadClassifier(name string) {
	overrides := loadOverrides()
	overrides.RemoveClassifier(name)
	saveOverrides(overrides)
	fmt.Printf("unloaded classifier: %s\n", name)
}

func runSetup() {
	fmt.Println("sai setup - BPF permissions for macOS")
	fmt.Println()
	fmt.Println("To capture network traffic, sai needs BPF access.")
	fmt.Println()
	fmt.Println("Run: sai install")
	fmt.Println()
	fmt.Println("Or manually:")
	fmt.Println("  # Create access_bpf group and add yourself")
	fmt.Println("  sudo dseditgroup -o create access_bpf")
	fmt.Println("  sudo dseditgroup -o edit -a $USER -t user access_bpf")
	fmt.Println()
	fmt.Println("  # Set BPF device permissions")
	fmt.Println("  sudo chgrp access_bpf /dev/bpf*")
	fmt.Println("  sudo chmod g+rw /dev/bpf*")
	fmt.Println()
	fmt.Println("Log out and back in for group membership to take effect.")
}

func runInstall() {
	if checkBPF() {
		fmt.Println("BPF access: ok")
		fmt.Println("sai is ready to use.")
		return
	}

	switch runtime.GOOS {
	case "darwin":
		runInstallDarwin()
	case "linux":
		runInstallLinux()
	default:
		fmt.Fprintf(os.Stderr, "error: unsupported OS: %s\n", runtime.GOOS)
		os.Exit(1)
	}
}

const (
	bpfGroup      = "access_bpf"
	bpfPlist      = "/Library/LaunchDaemons/com.knostic.sai.chmodbpf.plist"
	bpfSupportDir = "/Library/Application Support/Sai"
	bpfScript     = "/Library/Application Support/Sai/ChmodBPF"
	linuxGroup    = "sai"
)

func bpfHasGroupAccess() bool {
	info, err := os.Stat("/dev/bpf0")
	if err != nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	grp, err := user.LookupGroupId(fmt.Sprintf("%d", stat.Gid))
	if err != nil {
		return false
	}
	return grp.Name == bpfGroup && info.Mode().Perm()&0060 == 0060
}

func groupExists(name string) bool {
	return exec.Command("dscl", ".", "-read", "/Groups/"+name).Run() == nil
}

func createGroup(name string) error {
	gid := findFreeGID()
	if err := sudoRun("dscl", ".", "-create", "/Groups/"+name); err != nil {
		return err
	}
	return sudoRun("dscl", ".", "-create", "/Groups/"+name, "PrimaryGroupID", fmt.Sprintf("%d", gid))
}

func setBPFPermissions() error {
	if err := sudoRun("sh", "-c", "chgrp "+bpfGroup+" /dev/bpf*"); err != nil {
		return err
	}
	return sudoRun("sh", "-c", "chmod g+rw /dev/bpf*")
}

func userInGroup(username, group string) bool {
	out, err := exec.Command("id", "-Gn", username).Output()
	if err != nil {
		return false
	}
	for _, g := range strings.Fields(string(out)) {
		if g == group {
			return true
		}
	}
	return false
}

func addUserToGroup(username, group string) error {
	return sudoRun("dseditgroup", "-o", "edit", "-a", username, "-t", "user", group)
}

func runInstallDarwin() {
	username := currentUser()
	needLogout := false

	if bpfHasGroupAccess() {
		fmt.Printf("BPF devices: accessible by %s\n", bpfGroup)
	} else {
		if groupExists(bpfGroup) {
			fmt.Printf("Group %s: exists\n", bpfGroup)
		} else {
			fmt.Printf("Group %s: creating...\n", bpfGroup)
			if err := createGroup(bpfGroup); err != nil {
				fmt.Fprintf(os.Stderr, "error creating group: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Group %s: created\n", bpfGroup)
		}

		fmt.Println("Adding admin group to access_bpf...")
		if err := addAdminGroupToGroup(bpfGroup); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not add admin group: %v\n", err)
		}

		fmt.Println("BPF devices: setting permissions...")
		if err := setBPFPermissions(); err != nil {
			fmt.Fprintf(os.Stderr, "\nerror setting BPF permissions: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("BPF devices: accessible by %s\n", bpfGroup)
	}

	if userInGroup(username, bpfGroup) {
		fmt.Printf("User %s: in %s\n", username, bpfGroup)
	} else {
		fmt.Printf("User %s: adding to %s...\n", username, bpfGroup)
		if err := addUserToGroup(username, bpfGroup); err != nil {
			fmt.Fprintf(os.Stderr, "error adding user to group: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("User %s: added to %s\n", username, bpfGroup)
		needLogout = true
	}

	// Step 6: Offer LaunchDaemon
	if !launchDaemonExists() {
		fmt.Println()
		fmt.Print("Install LaunchDaemon to persist permissions across reboots? [y/N] ")
		reader := bufio.NewReader(os.Stdin)
		reply, _ := reader.ReadString('\n')
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(reply)), "y") {
			installLaunchDaemon()
		}
	}

	if needLogout {
		fmt.Println("\nLog out and back in for group membership to take effect.")
	}
}

func installLaunchDaemon() {
	// Find the ChmodBPF script in the same directory as the executable
	exePath, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error finding executable: %v\n", err)
		return
	}
	scriptSrc := filepath.Join(filepath.Dir(exePath), "..", "scripts", "ChmodBPF")
	plistSrc := filepath.Join(filepath.Dir(exePath), "..", "scripts", "com.knostic.sai.chmodbpf.plist")

	// Try current working directory if not found
	if _, err := os.Stat(scriptSrc); os.IsNotExist(err) {
		scriptSrc = "scripts/ChmodBPF"
		plistSrc = "scripts/com.knostic.sai.chmodbpf.plist"
	}

	if _, err := os.Stat(scriptSrc); os.IsNotExist(err) {
		fmt.Println("LaunchDaemon scripts not found. Skipping.")
		return
	}

	fmt.Println("Installing LaunchDaemon...")
	if err := sudoRun("mkdir", "-p", bpfSupportDir); err != nil {
		fmt.Fprintf(os.Stderr, "error creating support dir: %v\n", err)
		return
	}
	if err := sudoRun("cp", scriptSrc, bpfScript); err != nil {
		fmt.Fprintf(os.Stderr, "error copying script: %v\n", err)
		return
	}
	if err := sudoRun("chmod", "755", bpfScript); err != nil {
		fmt.Fprintf(os.Stderr, "error setting script permissions: %v\n", err)
		return
	}
	if err := sudoRun("chown", "root:wheel", bpfScript); err != nil {
		fmt.Fprintf(os.Stderr, "error setting script owner: %v\n", err)
		return
	}
	if err := sudoRun("cp", plistSrc, bpfPlist); err != nil {
		fmt.Fprintf(os.Stderr, "error copying plist: %v\n", err)
		return
	}
	if err := sudoRun("chown", "root:wheel", bpfPlist); err != nil {
		fmt.Fprintf(os.Stderr, "error setting plist owner: %v\n", err)
		return
	}
	if err := sudoRun("chmod", "644", bpfPlist); err != nil {
		fmt.Fprintf(os.Stderr, "error setting plist permissions: %v\n", err)
		return
	}
	_ = exec.Command("sudo", "launchctl", "bootout", "system", bpfPlist).Run()
	if err := sudoRun("launchctl", "bootstrap", "system", bpfPlist); err != nil {
		fmt.Fprintf(os.Stderr, "error loading LaunchDaemon: %v\n", err)
		return
	}
	fmt.Println("LaunchDaemon installed.")
}

func findFreeGID() int {
	gid := 100
	for {
		out, err := exec.Command("dscl", ".", "-search", "/Groups", "PrimaryGroupID", fmt.Sprintf("%d", gid)).Output()
		if err != nil || len(strings.TrimSpace(string(out))) == 0 {
			return gid
		}
		gid++
	}
}

func launchDaemonExists() bool {
	_, err := os.Stat(bpfPlist)
	return err == nil
}

func addAdminGroupToGroup(group string) error {
	return sudoRun("dseditgroup", "-o", "edit", "-a", "admin", "-t", "group", group)
}

func sudoRun(name string, args ...string) error {
	var cmd *exec.Cmd
	if os.Getuid() == 0 {
		cmd = exec.Command(name, args...)
	} else {
		cmd = exec.Command("sudo", append([]string{name}, args...)...)
	}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func currentUser() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	fmt.Fprintln(os.Stderr, "error: could not determine current user")
	os.Exit(1)
	return ""
}

func runInstallLinux() {
	username := currentUser()
	binary, _ := os.Executable()

	if !groupExistsLinux(linuxGroup) {
		fmt.Printf("Group %s: creating...\n", linuxGroup)
		if err := sudoRun("groupadd", "--system", linuxGroup); err != nil {
			fmt.Fprintf(os.Stderr, "error creating group: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Group %s: created\n", linuxGroup)
	} else {
		fmt.Printf("Group %s: exists\n", linuxGroup)
	}

	fmt.Printf("Binary: setting ownership to root:%s...\n", linuxGroup)
	_ = sudoRun("chown", "root:"+linuxGroup, binary)

	fmt.Println("Binary: setting capabilities...")
	if err := sudoRun("setcap", "cap_net_raw,cap_net_admin=eip", binary); err != nil {
		fmt.Println("setcap failed, falling back to setuid...")
		_ = sudoRun("chmod", "u=rwxs,g=rx,o=r", binary)
	} else {
		_ = sudoRun("chmod", "u=rwx,g=rx,o=r", binary)
		fmt.Println("Binary: capabilities set")
	}

	if !userInGroupLinux(username, linuxGroup) {
		fmt.Printf("User %s: adding to %s...\n", username, linuxGroup)
		_ = sudoRun("usermod", "-a", "-G", linuxGroup, username)
		fmt.Printf("User %s: added to %s\n", username, linuxGroup)
		fmt.Println("\nLog out and back in for group membership to take effect.")
	} else {
		fmt.Printf("User %s: in %s\n", username, linuxGroup)
	}
}

func groupExistsLinux(name string) bool {
	return exec.Command("getent", "group", name).Run() == nil
}

func userInGroupLinux(user, group string) bool {
	out, err := exec.Command("id", "-nG", user).Output()
	if err != nil {
		return false
	}
	for _, g := range strings.Fields(string(out)) {
		if g == group {
			return true
		}
	}
	return false
}

func runUninstall() {
	switch runtime.GOOS {
	case "darwin":
		runUninstallDarwin()
	case "linux":
		runUninstallLinux()
	default:
		fmt.Fprintf(os.Stderr, "error: unsupported OS: %s\n", runtime.GOOS)
		os.Exit(1)
	}
}

func runUninstallDarwin() {
	if launchDaemonExists() {
		fmt.Println("Removing LaunchDaemon...")
		_ = exec.Command("sudo", "launchctl", "bootout", "system", bpfPlist).Run()
		_ = sudoRun("rm", "-f", bpfPlist)
		_ = sudoRun("rm", "-rf", bpfSupportDir)
		fmt.Println("LaunchDaemon: removed")
	}

	if groupExists(bpfGroup) {
		fmt.Printf("Group %s: deleting...\n", bpfGroup)
		if err := sudoRun("dseditgroup", "-o", "delete", bpfGroup); err != nil {
			fmt.Fprintf(os.Stderr, "error deleting group: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Group %s: deleted\n", bpfGroup)
	} else {
		fmt.Printf("Group %s: not found\n", bpfGroup)
	}

	fmt.Println("\nBPF access removed. Permissions will reset on next reboot.")
}

func runUninstallLinux() {
	binary, _ := os.Executable()

	fmt.Println("Binary: removing capabilities...")
	_ = sudoRun("setcap", "-r", binary)

	_ = sudoRun("chmod", "755", binary)
	_ = sudoRun("chown", "root:root", binary)

	if groupExistsLinux(linuxGroup) {
		fmt.Printf("Group %s: deleting...\n", linuxGroup)
		if err := sudoRun("groupdel", linuxGroup); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not delete group: %v\n", err)
		} else {
			fmt.Printf("Group %s: deleted\n", linuxGroup)
		}
	} else {
		fmt.Printf("Group %s: not found\n", linuxGroup)
	}

	fmt.Println("\nCapabilities removed.")
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
	if iface, _ := cmd.Flags().GetString("interface"); iface != defaultInterface() {
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

func printEvent(ts time.Time, agent, process string, pid int, domain, source string, score sai.AIScore) {
	const format = "%s  %-10s  %-15s  %6d  %-35s  %-10s  %s"
	if isTTY && agent != "unknown" {
		fmt.Printf("\033[33m"+format+"\033[0m\n", ts.Format("15:04:05"), agent, process, pid, domain, source, score)
	} else {
		fmt.Printf(format+"\n", ts.Format("15:04:05"), agent, process, pid, domain, source, score)
	}
}

func baseDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) <= 2 {
		return domain
	}
	return strings.Join(parts[len(parts)-2:], ".")
}
