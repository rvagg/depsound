//go:build linux

package evidence

import (
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestExportSkipsFIFOInTree(t *testing.T) {
	cache := t.TempDir()
	tree := filepath.Join(cache, "tree")
	mustMkdir(t, tree)
	fifo := filepath.Join(tree, "pipe")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	manifest, err := Export(cache, filepath.Join(t.TempDir(), "evidence"), Input{Report: map[string]bool{}, Items: []Item{{Sources: []Source{{Tree: tree}}}}}, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Files) != 0 || len(manifest.Omissions) != 1 || !strings.Contains(manifest.Omissions[0].Reason, "special") {
		t.Fatalf("FIFO was retained: %+v", manifest)
	}
}
