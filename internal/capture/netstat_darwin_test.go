//go:build darwin

package capture

import "testing"

func TestParseNetstatHeader(t *testing.T) {
	tests := []struct {
		name       string
		header     string
		wantLocal  int
		wantForeig int
		wantPID    int
		wantOK     bool
	}{
		{
			name:       "standard macOS format",
			header:     "Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)          rxbytes      txbytes  rhiwat  shiwat    pid   epid state  options           gencnt    flags   flags1 usecnt rtncnt fltrs",
			wantLocal:  3,
			wantForeig: 4,
			wantPID:    10,
			wantOK:     true,
		},
		{
			name:       "hypothetical format with pid at different index",
			header:     "Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)     pid   epid",
			wantLocal:  3,
			wantForeig: 4,
			wantPID:    6,
			wantOK:     true,
		},
		{
			name:       "no pid column",
			header:     "Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)",
			wantLocal:  3,
			wantForeig: 4,
			wantPID:    -1,
			wantOK:     false,
		},
		{
			name:       "macOS 26 format with process:pid",
			header:     "Proto Recv-Q Send-Q  Local Address                                 Foreign Address                               (state)          rxbytes      txbytes  rhiwat  shiwat          process:pid    state  options           gencnt    flags   flags1 usecnt rtncnt fltrs",
			wantLocal:  3,
			wantForeig: 4,
			wantPID:    10,
			wantOK:     true,
		},
		{
			name:   "empty header",
			header: "",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cols, ok := parseNetstatHeader(tt.header)
			if ok != tt.wantOK {
				t.Fatalf("parseNetstatHeader() ok = %v, want %v", ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if cols.localAddr != tt.wantLocal {
				t.Errorf("localAddr = %d, want %d", cols.localAddr, tt.wantLocal)
			}
			if cols.foreignAddr != tt.wantForeig {
				t.Errorf("foreignAddr = %d, want %d", cols.foreignAddr, tt.wantForeig)
			}
			if cols.pid != tt.wantPID {
				t.Errorf("pid = %d, want %d", cols.pid, tt.wantPID)
			}
		})
	}
}

func TestParseNetstatLine(t *testing.T) {
	cols := netstatColumns{localAddr: 3, foreignAddr: 4, pid: 10}

	tests := []struct {
		name     string
		line     string
		wantPort uint16
		wantPID  uint32
		wantOK   bool
	}{
		{
			name:     "standard ESTABLISHED connection to 443",
			line:     "tcp4       0    573  192.168.0.242.52962    142.250.75.91.443      ESTABLISHED            0          573  131600  131600   8697      0 00102 00000000 0000000000b0c7a7 00000081 04000900      2      0 000000",
			wantPort: 52962,
			wantPID:  8697,
			wantOK:   true,
		},
		{
			name:   "not targeting port 443",
			line:   "tcp4       0      0  192.168.0.242.52962    142.250.75.91.80       ESTABLISHED            0          573  131600  131600   8697      0 00102 00000000 0000000000b0c7a7 00000081 04000900      2      0 000000",
			wantOK: false,
		},
		{
			name:   "pid is 0",
			line:   "tcp4       0      0  192.168.0.242.52962    142.250.75.91.443      ESTABLISHED            0            0  131600  131600      0      0 00102 00000000 0000000000b0c7a7 00000081 04000900      2      0 000000",
			wantOK: false,
		},
		{
			name:   "too few fields",
			line:   "tcp4 0 0 local foreign",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			port, pid, ok := parseNetstatLine(tt.line, cols)
			if ok != tt.wantOK {
				t.Fatalf("parseNetstatLine() ok = %v, want %v", ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if port != tt.wantPort {
				t.Errorf("port = %d, want %d", port, tt.wantPort)
			}
			if pid != tt.wantPID {
				t.Errorf("pid = %d, want %d", pid, tt.wantPID)
			}
		})
	}
}

func TestParseNetstatLineWithShiftedPID(t *testing.T) {
	cols := netstatColumns{localAddr: 3, foreignAddr: 4, pid: 6}
	line := "tcp4       0      0  192.168.0.242.52962    142.250.75.91.443      ESTABLISHED   1234      0"

	port, pid, ok := parseNetstatLine(line, cols)
	if !ok {
		t.Fatal("expected ok")
	}
	if port != 52962 {
		t.Errorf("port = %d, want 52962", port)
	}
	if pid != 1234 {
		t.Errorf("pid = %d, want 1234", pid)
	}
}

func TestParseNetstatLineMacOS26ProcessPID(t *testing.T) {
	cols := netstatColumns{localAddr: 3, foreignAddr: 4, pid: 10}
	line := "tcp4       0      0  192.168.1.217.51329    3.18.56.94.443         ESTABLISHED         9720          862  131072  131768         osqueryd:1282   00182 00000008 0000000000381127 20000081 04000800      3      0 000004"

	port, pid, ok := parseNetstatLine(line, cols)
	if !ok {
		t.Fatal("expected ok")
	}
	if port != 51329 {
		t.Errorf("port = %d, want 51329", port)
	}
	if pid != 1282 {
		t.Errorf("pid = %d, want 1282", pid)
	}
}
