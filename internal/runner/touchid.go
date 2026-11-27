package runner

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// PAMFiles are where macOS configures authentication for sudo. Apple's
// /etc/pam.d/sudo includes sudo_local, the file meant for local changes such
// as Touch ID, which system updates keep.
var PAMFiles = []string{"/etc/pam.d/sudo_local", "/etc/pam.d/sudo"}

// TouchIDEnabled reports whether sudo on this computer accepts Touch ID: an
// auth line for pam_tid.so in one of files that is not commented out. It is
// false on every system but macOS.
//
// psudo tries Touch ID only when this is true. Without pam_tid, the attempt
// would be a sudo -v with an empty stdin, which only adds a failed
// authentication to the log.
func TouchIDEnabled(files ...string) bool {
	if runtime.GOOS != "darwin" {
		return false
	}
	for _, f := range files {
		if pamHasTouchID(f) {
			return true
		}
	}
	return false
}

func pamHasTouchID(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != "auth" {
			continue
		}
		// auth <control> <module> [args]: the control may be [a=b ...].
		for _, m := range fields[2:] {
			if base := filepath.Base(m); base == "pam_tid.so" || strings.HasPrefix(base, "pam_tid.so.") {
				return true
			}
		}
	}
	return false
}
