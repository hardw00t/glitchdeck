package execrun

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteReportReplacesPermissiveFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file permission bits")
	}
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, nil, 0644); err != nil {
		t.Fatal(err)
	}
	if err := WriteReport(path, NewEnvelope("exec", "", "")); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Mode().Perm(); got != 0600 {
		t.Fatalf("report mode = %o, want 600", got)
	}
}
