//go:build linux

package capture

import (
	"bufio"
	"encoding/hex"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

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
				s.updateStatsFromSS()
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

func (s *sniMonitor) updateStatsFromSS() {
	cmd := exec.Command("ss", "-tni", "state", "established", "dport", "=", ":443")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return
	}
	if err := cmd.Start(); err != nil {
		return
	}

	scanner := bufio.NewScanner(stdout)
	var currentKey *types.ConnectionKey
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			if currentKey != nil {
				bytesIn, bytesOut := parseSSStats(line)
				if bytesIn > 0 || bytesOut > 0 {
					s.traffic.UpdateFromNetstat(*currentKey, bytesIn, bytesOut, 0, 0)
				}
			}
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			currentKey = nil
			continue
		}

		localIP, localPort := parseSSAddr(fields[3])
		foreignIP, foreignPort := parseSSAddr(fields[4])
		if localPort == 0 || foreignPort == 0 {
			currentKey = nil
			continue
		}

		key := types.ConnectionKey{
			SrcIP:   localIP,
			DstIP:   foreignIP,
			SrcPort: localPort,
			DstPort: foreignPort,
		}
		currentKey = &key
	}
	cmd.Wait()
}

func parseSSAddr(addr string) (string, uint16) {
	lastColon := strings.LastIndex(addr, ":")
	if lastColon < 0 {
		return "", 0
	}
	ip := addr[:lastColon]
	ip = strings.TrimPrefix(ip, "[")
	ip = strings.TrimSuffix(ip, "]")
	port, err := strconv.Atoi(addr[lastColon+1:])
	if err != nil || port <= 0 || port > 65535 {
		return "", 0
	}
	return ip, uint16(port)
}

func parseSSStats(line string) (bytesIn, bytesOut int64) {
	fields := strings.Fields(line)
	for _, f := range fields {
		if strings.HasPrefix(f, "bytes_received:") {
			bytesIn, _ = strconv.ParseInt(strings.TrimPrefix(f, "bytes_received:"), 10, 64)
		} else if strings.HasPrefix(f, "bytes_sent:") {
			bytesOut, _ = strconv.ParseInt(strings.TrimPrefix(f, "bytes_sent:"), 10, 64)
		}
	}
	return
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
	path, err := os.Readlink("/proc/" + strconv.Itoa(int(pid)) + "/exe")
	if err != nil {
		return ""
	}
	return path
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

func (s *sniMonitor) refreshPortCache() {
	cache := make(map[uint16]uint32)

	data, err := os.ReadFile("/proc/net/tcp")
	if err == nil {
		parseNetTCP(data, cache)
	}

	data, err = os.ReadFile("/proc/net/tcp6")
	if err == nil {
		parseNetTCP(data, cache)
	}

	s.mu.Lock()
	s.portCache = cache
	s.mu.Unlock()
}

func parseNetTCP(data []byte, cache map[uint16]uint32) {
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Scan()
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}

		remoteAddr := fields[2]
		if !strings.HasSuffix(remoteAddr, ":01BB") {
			continue
		}

		localParts := strings.Split(fields[1], ":")
		if len(localParts) != 2 {
			continue
		}
		portHex := localParts[1]
		portBytes, err := hex.DecodeString(portHex)
		if err != nil || len(portBytes) != 2 {
			continue
		}
		port := uint16(portBytes[0])<<8 | uint16(portBytes[1])

		inode := fields[9]

		pid := findPIDByInode(inode)
		if pid > 0 {
			cache[port] = pid
		}
	}
}

func findPIDByInode(inode string) uint32 {
	procDirs, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}

	target := "socket:[" + inode + "]"
	for _, dir := range procDirs {
		if !dir.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(dir.Name())
		if err != nil {
			continue
		}

		fdPath := "/proc/" + dir.Name() + "/fd"
		fds, err := os.ReadDir(fdPath)
		if err != nil {
			continue
		}

		for _, fd := range fds {
			link, err := os.Readlink(fdPath + "/" + fd.Name())
			if err != nil {
				continue
			}
			if link == target {
				return uint32(pid)
			}
		}
	}
	return 0
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
