package extract

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Zip extracts src into dest. Unlike tarballs, Go module zips declare
// their root a priori: every entry must live under requiredPrefix
// ("module@version/"), so there is no discovery pass; entries outside
// the prefix are hostile by spec and recorded, not extracted.
func Zip(src, dest, requiredPrefix string, lim Limits) (*Report, error) {
	zr, err := zip.OpenReader(src)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", src, err)
	}
	defer zr.Close()

	rep := &Report{Prefix: requiredPrefix}
	prefix := requiredPrefix + "/"
	// The go toolchain (x/mod/zip) rejects duplicate and case-colliding
	// entries outright, so a zip carrying them describes a module the
	// ecosystem would never install: record as hostile, extract first
	// occurrence only.
	seen := map[string]string{}
	var links, hostile cappedList
	entries := 0 // files AND dirs: a directory flood exhausts inodes too
	for _, f := range zr.File {
		name, err := sanitize(f.Name)
		if err != nil {
			hostile.add(fmt.Sprintf("%q: %v", f.Name, err))
			continue
		}
		if name == "" || name == requiredPrefix {
			continue
		}
		rel, ok := strings.CutPrefix(name, prefix)
		if !ok || rel == "" {
			hostile.add(fmt.Sprintf("%q: outside module prefix %q", f.Name, requiredPrefix))
			continue
		}
		target := filepath.Join(dest, filepath.FromSlash(rel))

		mode := f.Mode()
		switch {
		case mode.IsDir() || strings.HasSuffix(f.Name, "/"):
			if entries++; entries > lim.MaxFiles {
				return nil, fmt.Errorf("%s: exceeds %d entry limit", src, lim.MaxFiles)
			}
			if err := os.MkdirAll(target, 0o755); err != nil {
				return nil, err
			}
		case mode&os.ModeSymlink != 0:
			links.add(f.Name)
		case mode.IsRegular():
			if prior, dup := seen[strings.ToLower(rel)]; dup {
				hostile.add(fmt.Sprintf("%q: duplicate or case-colliding entry (collides with %q); go toolchain would reject this zip", f.Name, prior))
				continue
			}
			seen[strings.ToLower(rel)] = f.Name
			rep.Files++
			if entries++; entries > lim.MaxFiles {
				return nil, fmt.Errorf("%s: exceeds %d entry limit", src, lim.MaxFiles)
			}
			// declared size is attacker-controlled; compare in uint64
			// (an int64 cast could overflow negative and bypass), and
			// enforce the cap on actual bytes too
			if f.UncompressedSize64 > uint64(lim.MaxFileBytes) {
				return nil, fmt.Errorf("%s: %s: declares %d bytes, exceeds %d byte file limit", src, rel, f.UncompressedSize64, lim.MaxFileBytes)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return nil, err
			}
			rc, err := f.Open()
			if err != nil {
				return nil, fmt.Errorf("%s: %s: %w", src, rel, err)
			}
			n, err := writeCapped(target, rc, fileBudget(lim, rep.TotalBytes))
			rc.Close()
			if err != nil {
				return nil, fmt.Errorf("%s: %s: %w", src, rel, err)
			}
			rep.TotalBytes += n
			if rep.TotalBytes > lim.MaxTotalBytes {
				return nil, fmt.Errorf("%s: exceeds %d byte total limit", src, lim.MaxTotalBytes)
			}
		default:
			// char/block/fifo/etc have no business in a package; skip
		}
	}
	rep.SkippedLinks, rep.HostileEntries = links.list(), hostile.list()
	return rep, nil
}
