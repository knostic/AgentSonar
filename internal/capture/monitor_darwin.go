//go:build darwin

package capture

/*
#include <libproc.h>
#include <sys/proc_info.h>
#include <stdlib.h>
*/
import "C"

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/knostic/agentsonar/types"
)

type sniMonitor struct {
	cfg          types.Config
	handle       *pcap.Handle
	events       chan types.Event
	seen         map[string]time.Time
	sniToConn    map[string]types.ConnectionKey
	ipToHost     map[string]string
	dnsQueryTime map[string]time.Time
	connPID      map[types.ConnectionKey]int
	portCache    map[uint16]uint32
	traffic      *trafficAnalyzer
	mu           sync.Mutex
	done         chan struct{}
}

func NewSNIMonitor(cfg types.Config) *sniMonitor {
	return &sniMonitor{
		cfg:          cfg,
		events:       make(chan types.Event, 100),
		seen:         make(map[string]time.Time),
		sniToConn:    make(map[string]types.ConnectionKey),
		ipToHost:     make(map[string]string),
		dnsQueryTime: make(map[string]time.Time),
		connPID:      make(map[types.ConnectionKey]int),
		portCache:    make(map[uint16]uint32),
		traffic:      newTrafficAnalyzer(),
		done:         make(chan struct{}),
	}
}

func (s *sniMonitor) Start() error {
	handle, err := pcap.OpenLive(s.cfg.Interface, 1600, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	s.handle = handle

	if err := handle.SetBPFFilter("(tcp dst port 443 and tcp[((tcp[12:1] & 0xf0) >> 2):1] = 0x16) or udp port 53"); err != nil {
		handle.Close()
		return err
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	go func() {
		for packet := range packetSource.Packets() {
			s.processPacket(packet)
		}
	}()

	s.startNetstatPoller(2 * time.Second)
	s.startMapCleanup(5 * time.Minute)
	s.startStreamingDetection(1 * time.Second)

	return nil
}

func (s *sniMonitor) startNetstatPoller(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-s.done:
				return
			case <-ticker.C:
				s.updateStatsFromNetstat()
			}
		}
	}()
}

func (s *sniMonitor) startMapCleanup(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-s.done:
				return
			case <-ticker.C:
				s.cleanupStaleMaps()
			}
		}
	}()
}

func (s *sniMonitor) cleanupStaleMaps() {
	s.mu.Lock()
	defer s.mu.Unlock()

	staleThreshold := 10 * time.Minute
	now := time.Now()

	for host, t := range s.dnsQueryTime {
		if now.Sub(t) > staleThreshold {
			delete(s.dnsQueryTime, host)
		}
	}

	for sni, t := range s.seen {
		if now.Sub(t) > staleThreshold {
			delete(s.seen, sni)
			if connKey, ok := s.sniToConn[sni]; ok {
				delete(s.sniToConn, sni)
				delete(s.connPID, connKey)
			}
		}
	}
}

func (s *sniMonitor) updateStatsFromNetstat() {
	cmd := exec.Command("netstat", "-anv", "-p", "tcp")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return
	}
	if err := cmd.Start(); err != nil {
		return
	}

	scanner := bufio.NewScanner(stdout)
	scanner.Scan()
	if !scanner.Scan() {
		cmd.Wait()
		return
	}
	headerFields := strings.Fields(scanner.Text())
	statCols := parseNetstatStatColumns(headerFields)
	cols, ok := parseNetstatHeader(scanner.Text())
	if !ok {
		cmd.Wait()
		return
	}

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, ".443") {
			continue
		}
		fields := strings.Fields(line)
		minFields := max(cols.foreignAddr+1, statCols.minFields)
		if len(fields) < minFields {
			continue
		}

		foreign := fields[cols.foreignAddr]
		if !strings.HasSuffix(foreign, ".443") {
			continue
		}

		local := fields[cols.localAddr]
		localIP, localPort := parseNetstatAddr(local)
		foreignIP, foreignPort := parseNetstatAddr(foreign)
		if localPort == 0 || foreignPort == 0 {
			continue
		}

		var rxBytes, txBytes int64
		var rxPkts, txPkts int
		if statCols.rxBytes >= 0 && statCols.rxBytes < len(fields) {
			rxBytes, _ = strconv.ParseInt(fields[statCols.rxBytes], 10, 64)
		}
		if statCols.txBytes >= 0 && statCols.txBytes < len(fields) {
			txBytes, _ = strconv.ParseInt(fields[statCols.txBytes], 10, 64)
		}
		if statCols.rxPkts >= 0 && statCols.rxPkts < len(fields) {
			rxPkts, _ = strconv.Atoi(fields[statCols.rxPkts])
		}
		if statCols.txPkts >= 0 && statCols.txPkts < len(fields) {
			txPkts, _ = strconv.Atoi(fields[statCols.txPkts])
		}

		key := types.ConnectionKey{
			SrcIP:   localIP,
			DstIP:   foreignIP,
			SrcPort: localPort,
			DstPort: foreignPort,
		}
		s.traffic.UpdateFromNetstat(key, rxBytes, txBytes, rxPkts, txPkts)
	}
	cmd.Wait()
}

type netstatStatColumns struct {
	rxBytes   int
	txBytes   int
	rxPkts    int
	txPkts    int
	minFields int
}

func parseNetstatStatColumns(fields []string) netstatStatColumns {
	cols := netstatStatColumns{rxBytes: -1, txBytes: -1, rxPkts: -1, txPkts: -1}

	multiWordAdjustment := 0
	for i, f := range fields {
		fl := strings.ToLower(f)
		if fl == "address" {
			multiWordAdjustment++
			continue
		}
		dataIdx := i - multiWordAdjustment
		switch fl {
		case "rxbytes":
			cols.rxBytes = dataIdx
		case "txbytes":
			cols.txBytes = dataIdx
		case "rxpackets":
			cols.rxPkts = dataIdx
		case "txpackets":
			cols.txPkts = dataIdx
		}
	}
	for _, idx := range []int{cols.rxBytes, cols.txBytes, cols.rxPkts, cols.txPkts} {
		if idx+1 > cols.minFields {
			cols.minFields = idx + 1
		}
	}
	return cols
}

func parseNetstatAddr(addr string) (string, uint16) {
	lastDot := strings.LastIndex(addr, ".")
	if lastDot < 0 {
		return "", 0
	}
	ip := addr[:lastDot]
	port, err := strconv.Atoi(addr[lastDot+1:])
	if err != nil || port <= 0 || port > 65535 {
		return "", 0
	}
	return ip, uint16(port)
}

func (s *sniMonitor) processPacket(packet gopacket.Packet) {
	var srcIP, dstIP string
	if ipv4 := packet.Layer(layers.LayerTypeIPv4); ipv4 != nil {
		ip := ipv4.(*layers.IPv4)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
	} else if ipv6 := packet.Layer(layers.LayerTypeIPv6); ipv6 != nil {
		ip := ipv6.(*layers.IPv6)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		srcPort := uint16(tcp.SrcPort)
		dstPort := uint16(tcp.DstPort)

		if len(tcp.Payload) > 0 && dstPort == 443 {
			if ch := ParseClientHello(tcp.Payload); ch != nil && ch.SNI != "" {
				connKey := types.ConnectionKey{SrcIP: srcIP, DstIP: dstIP, SrcPort: srcPort, DstPort: dstPort}
				s.traffic.TrackConnection(connKey)
				s.emitTLSEvent(ch, srcPort, connKey)
			}
		}
		return
	}

	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		srcPort := uint16(udp.SrcPort)
		dstPort := uint16(udp.DstPort)

		if dstPort == 53 && len(udp.Payload) > 0 {
			if domain := ParseDNSQuery(udp.Payload); domain != "" {
				s.mu.Lock()
				s.dnsQueryTime[domain] = time.Now()
				s.mu.Unlock()
				s.emitDNSEvent(domain, srcPort)
			}
		}

		if srcPort == 53 && len(udp.Payload) > 0 {
			if domain, ips := ParseDNSResponseIPs(udp.Payload); domain != "" && len(ips) > 0 {
				s.mu.Lock()
				for _, ip := range ips {
					s.ipToHost[ip] = domain
				}
				s.mu.Unlock()
			}
		}
	}
}

func (s *sniMonitor) emitTLSEvent(ch *ClientHello, srcPort uint16, connKey types.ConnectionKey) {
	sni := ch.SNI

	pid := s.lookupPID(srcPort)
	procPath := getProcessPath(pid)
	if !s.cfg.EnablePID0 && (pid == 0 || procPath == "") {
		if s.cfg.Verbose {
			fmt.Fprintf(os.Stderr, "[verbose] dropping TLS event for %s: pid=%d procPath=%q (srcPort=%d)\n", sni, pid, procPath, srcPort)
		}
		return
	}

	s.mu.Lock()
	s.ipToHost[connKey.DstIP] = sni
	s.sniToConn[sni] = connKey
	s.connPID[connKey] = int(pid)
	if lastSeen, ok := s.seen[sni]; ok && time.Since(lastSeen) < time.Minute {
		s.mu.Unlock()
		return
	}
	s.seen[sni] = time.Now()
	s.mu.Unlock()

	ja4 := ch.JA4()
	procName := extractProcessName(procPath)

	event := types.Event{
		Timestamp:  time.Now(),
		PID:        int(pid),
		Process:    procName,
		BinaryPath: procPath,
		Domain:     sni,
		Source:     "tls",
		JA4:        ja4,
		Extras:     make(map[string]string),
	}

	isProgrammatic, _ := ch.IsLikelyProgrammatic()
	event.Extras["programmatic"] = strconv.FormatBool(isProgrammatic)

	select {
	case s.events <- event:
	default:
	}
}

func (s *sniMonitor) emitDNSEvent(domain string, srcPort uint16) {
	s.mu.Lock()
	if lastSeen, ok := s.seen["dns:"+domain]; ok && time.Since(lastSeen) < time.Minute {
		s.mu.Unlock()
		return
	}
	s.seen["dns:"+domain] = time.Now()
	s.mu.Unlock()

	pid := s.lookupPID(srcPort)
	procPath := getProcessPath(pid)
	if !s.cfg.EnablePID0 && (pid == 0 || procPath == "") {
		if s.cfg.Verbose {
			fmt.Fprintf(os.Stderr, "[verbose] dropping DNS event for %s: pid=%d procPath=%q (srcPort=%d)\n", domain, pid, procPath, srcPort)
		}
		return
	}

	procName := extractProcessName(procPath)

	event := types.Event{
		Timestamp:  time.Now(),
		PID:        int(pid),
		Process:    procName,
		BinaryPath: procPath,
		Domain:     domain,
		Source:     "dns",
	}

	select {
	case s.events <- event:
	default:
	}
}

func (s *sniMonitor) startStreamingDetection(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		emitted := make(map[string]time.Time)

		for {
			select {
			case <-s.done:
				return
			case <-ticker.C:
				streaming := s.getStreamingConnections()
				for sni, features := range streaming {
					if last, ok := emitted[sni]; ok && time.Since(last) < 30*time.Second {
						continue
					}
					emitted[sni] = time.Now()
					s.emitStreamingEvent(sni, features)
				}
			}
		}
	}()
}

func (s *sniMonitor) getStreamingConnections() map[string]*types.TrafficFeatures {
	s.mu.Lock()
	sniToKey := make(map[string]types.ConnectionKey)
	for sni, key := range s.sniToConn {
		sniToKey[sni] = key
	}
	ipToHostCopy := make(map[string]string)
	for ip, host := range s.ipToHost {
		ipToHostCopy[ip] = host
	}
	connPIDCopy := make(map[types.ConnectionKey]int)
	for key, pid := range s.connPID {
		connPIDCopy[key] = pid
	}
	s.mu.Unlock()

	keyToSNI := make(map[types.ConnectionKey]string)
	for sni, key := range sniToKey {
		keyToSNI[key] = sni
	}

	result := make(map[string]*types.TrafficFeatures)
	activeConns := s.traffic.GetAllActive(30 * time.Second)

	for key, features := range activeConns {
		if !features.IsStreaming || features.Duration == 0 {
			continue
		}
		lastActivity := s.traffic.GetLastActivity(key)
		if time.Since(lastActivity) >= 5*time.Second {
			continue
		}

		name := keyToSNI[key]
		if name == "" {
			name = ipToHostCopy[key.DstIP]
		}
		if name == "" {
			name = key.DstIP
		}

		features.DstIP = key.DstIP
		features.ConcurrentConns = s.traffic.CountConnectionsToIP(key.DstIP, 30*time.Second)
		if pid, ok := connPIDCopy[key]; ok {
			features.IsNewConn = true
			features.PID = pid
		}

		result[name] = features
	}
	return result
}

func (s *sniMonitor) emitStreamingEvent(sni string, features *types.TrafficFeatures) {
	procPath := getProcessPath(uint32(features.PID))
	if !s.cfg.EnablePID0 && (features.PID == 0 || procPath == "") {
		if s.cfg.Verbose {
			fmt.Fprintf(os.Stderr, "[verbose] dropping streaming event for %s: pid=%d procPath=%q\n", sni, features.PID, procPath)
		}
		return
	}

	procName := extractProcessName(procPath)

	event := types.Event{
		Timestamp:  time.Now(),
		PID:        features.PID,
		Process:    procName,
		BinaryPath: procPath,
		Domain:     sni,
		Source:     "streaming",
		Extras: map[string]string{
			"duration_ms": strconv.Itoa(int(features.Duration.Milliseconds())),
			"bytes_in":    strconv.FormatInt(features.BytesIn, 10),
			"bytes_out":   strconv.FormatInt(features.BytesOut, 10),
			"packets_in":  strconv.Itoa(features.PacketsIn),
			"packets_out": strconv.Itoa(features.PacketsOut),
			"concurrent":  strconv.Itoa(features.ConcurrentConns),
		},
	}

	select {
	case s.events <- event:
	default:
	}
}

func (s *sniMonitor) lookupPID(port uint16) uint32 {
	pid := s.portCache[port]
	if pid != 0 {
		return pid
	}
	s.refreshPortCache()
	return s.portCache[port]
}

func getProcessPath(pid uint32) string {
	if pid == 0 {
		return ""
	}
	buf := make([]byte, C.PROC_PIDPATHINFO_MAXSIZE)
	ret := C.proc_pidpath(C.int(pid), unsafe.Pointer(&buf[0]), C.uint32_t(len(buf)))
	if ret <= 0 {
		return ""
	}
	return string(buf[:ret])
}

func extractProcessName(path string) string {
	if path == "" {
		return ""
	}
	idx := strings.LastIndex(path, "/")
	if idx >= 0 {
		return path[idx+1:]
	}
	return path
}

type netstatColumns struct {
	localAddr   int
	foreignAddr int
	pid         int
}

func parseNetstatHeader(header string) (netstatColumns, bool) {
	cols := netstatColumns{localAddr: -1, foreignAddr: -1, pid: -1}
	lower := strings.ToLower(header)
	headerFields := strings.Fields(lower)
	headerWordCount := len(headerFields)
	if headerWordCount == 0 {
		return cols, false
	}

	type target struct {
		keyword string
		dest    *int
	}
	targets := []target{
		{"local", &cols.localAddr},
		{"foreign", &cols.foreignAddr},
		{"pid", &cols.pid},
	}
	for _, t := range targets {
		for i, f := range headerFields {
			if f == t.keyword || strings.HasSuffix(f, ":"+t.keyword) {
				*t.dest = i
				break
			}
		}
		if *t.dest < 0 {
			return cols, false
		}
	}

	// NOTE: header has multi-word columns (e.g. "Local Address", "Foreign Address")
	// which means header word count > data field count.
	// We compute each target's distance from the end of the header,
	// then map it to the same distance from the end in data lines.
	// We calibrate using a known data field count offset:
	// multiWordCols = number of multi-word headers = headerWordCount - dataFieldCount
	// For each target at header index h, data index = h - (multi-word columns before h)
	// We detect multi-word columns by looking for words that are not plausible column names
	// following another word (like "Address" after "Local").
	// Simpler: count known multi-word pairs before each target.
	multiWordPairs := []string{"address"}
	for _, t := range targets {
		adjustment := 0
		for i := 0; i < *t.dest; i++ {
			for _, mw := range multiWordPairs {
				if headerFields[i] == mw {
					adjustment++
				}
			}
		}
		*t.dest -= adjustment
	}

	return cols, true
}

func parseNetstatLine(line string, cols netstatColumns) (port uint16, pid uint32, ok bool) {
	if !strings.Contains(line, ".443") {
		return 0, 0, false
	}
	fields := strings.Fields(line)
	minFields := cols.pid + 1
	if cols.foreignAddr+1 > minFields {
		minFields = cols.foreignAddr + 1
	}
	if len(fields) < minFields {
		return 0, 0, false
	}

	foreign := fields[cols.foreignAddr]
	if !strings.HasSuffix(foreign, ".443") {
		return 0, 0, false
	}

	local := fields[cols.localAddr]
	lastDot := strings.LastIndex(local, ".")
	if lastDot < 0 {
		return 0, 0, false
	}
	p, err := strconv.Atoi(local[lastDot+1:])
	if err != nil || p <= 0 {
		return 0, 0, false
	}

	pidStr := fields[cols.pid]
	if colonIdx := strings.LastIndex(pidStr, ":"); colonIdx >= 0 {
		pidStr = pidStr[colonIdx+1:]
	}
	pidVal, err := strconv.Atoi(pidStr)
	if err != nil || pidVal <= 0 {
		return 0, 0, false
	}

	return uint16(p), uint32(pidVal), true
}

func (s *sniMonitor) refreshPortCache() {
	cache := make(map[uint16]uint32)

	cmd := exec.Command("netstat", "-anv", "-p", "tcp")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return
	}
	if err := cmd.Start(); err != nil {
		return
	}

	scanner := bufio.NewScanner(stdout)
	// NOTE: skip first line ("Active Internet connections ...")
	scanner.Scan()
	// NOTE: parse header to find column indices
	if !scanner.Scan() {
		cmd.Wait()
		return
	}
	cols, ok := parseNetstatHeader(scanner.Text())
	if !ok {
		if s.cfg.Verbose {
			fmt.Fprintf(os.Stderr, "[verbose] netstat: could not parse header, PID resolution disabled\n")
		}
		cmd.Wait()
		return
	}

	for scanner.Scan() {
		port, pid, ok := parseNetstatLine(scanner.Text(), cols)
		if ok {
			cache[port] = pid
		}
	}
	cmd.Wait()

	s.mu.Lock()
	s.portCache = cache
	s.mu.Unlock()
}

func (s *sniMonitor) Stop() {
	close(s.done)
	if s.handle != nil {
		s.handle.Close()
	}
}

func (s *sniMonitor) Events() <-chan types.Event {
	return s.events
}
