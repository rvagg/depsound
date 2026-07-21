// Package extract unpacks downloaded archives on the assumption that their
// contents are hostile: traversal, links and bombs are rejected or skipped,
// and the result is inert data, never a working directory.
package extract

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

type Limits struct {
	MaxFiles      int
	MaxFileBytes  int64
	MaxTotalBytes int64
}

// DefaultLimits bound decompression, not legitimate packages: the Go
// proxy caps module zips at 500 MiB and crates.io at 10 MiB compressed,
// and the largest real npm artifacts unpack to a few hundred MiB. Two
// trees extract per run, so worst case disk is 2x MaxTotalBytes. If a
// legitimate artifact ever trips these, the error names the limit and
// the limit becomes a flag.
var DefaultLimits = Limits{
	MaxFiles:      200_000,
	MaxFileBytes:  512 << 20, // 512 MiB
	MaxTotalBytes: 1 << 30,   // 1 GiB
}

type Report struct {
	Files        int
	TotalBytes   int64
	SkippedLinks []string // symlink/hardlink entries recorded, never created
	// HostileEntries are members with traversal, absolute or control-byte
	// names: skipped and reported rather than aborting, because an
	// artifact carrying them is exactly the one whose remaining content
	// most needs analyzing.
	HostileEntries []string
	Prefix         string // common root stripped from all entries, e.g. "package"
}

// maxReportEntries caps each report list: a hostile archive can carry
// millions of bad members, and the report must name examples, never mirror
// the flood. The overflow is summarised, not dropped.
const maxReportEntries = 100

// cappedList records up to maxReportEntries then counts the rest.
type cappedList struct {
	entries    []string
	suppressed int
}

func (c *cappedList) add(s string) {
	if len(c.entries) < maxReportEntries {
		c.entries = append(c.entries, s)
		return
	}
	c.suppressed++
}

func (c *cappedList) list() []string {
	if c.suppressed > 0 {
		return append(c.entries, fmt.Sprintf("(+%d more suppressed)", c.suppressed))
	}
	return c.entries
}

// TarGz extracts src into dest. A common root directory shared by every
// entry (npm's package/, crates' name-version/) is stripped so trees from
// different versions diff cleanly. That requires knowing the common root
// before writing any file, and tar is a stream, so the archive is read
// twice: commonRoot walks headers only, then the loop below extracts.
// Decompressing twice is cheaper than buffering the whole archive.
func TarGz(src, dest string, lim Limits) (*Report, error) {
	prefix, err := commonRoot(src, lim) // pass 1: headers only
	if err != nil {
		return nil, err
	}
	f, err := os.Open(src)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", src, err)
	}
	defer gz.Close()

	rep := &Report{Prefix: prefix}
	var links, hostile cappedList
	entries := 0 // files AND dirs: a directory flood exhausts inodes too
	tr := tar.NewReader(gz)
	for { // pass 2: extract
		hdr, err := tr.Next()
		if err == io.EOF {
			rep.SkippedLinks, rep.HostileEntries = links.list(), hostile.list()
			return rep, nil
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", src, err)
		}
		name, err := sanitize(hdr.Name)
		if err != nil {
			hostile.add(fmt.Sprintf("%q: %v", hdr.Name, err))
			continue
		}
		if prefix != "" {
			name = strings.TrimPrefix(name, prefix)
			name = strings.TrimPrefix(name, "/")
			if name == "" {
				continue
			}
		}
		target := filepath.Join(dest, filepath.FromSlash(name))

		switch hdr.Typeflag {
		case tar.TypeDir:
			if entries++; entries > lim.MaxFiles {
				return nil, fmt.Errorf("%s: exceeds %d entry limit", src, lim.MaxFiles)
			}
			if err := os.MkdirAll(target, 0o755); err != nil {
				return nil, err
			}
		case tar.TypeReg:
			rep.Files++
			if entries++; entries > lim.MaxFiles {
				return nil, fmt.Errorf("%s: exceeds %d entry limit", src, lim.MaxFiles)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return nil, err
			}
			n, err := writeCapped(target, tr, fileBudget(lim, rep.TotalBytes))
			if err != nil {
				return nil, fmt.Errorf("%s: %s: %w", src, name, err)
			}
			rep.TotalBytes += n
			if rep.TotalBytes > lim.MaxTotalBytes {
				return nil, fmt.Errorf("%s: exceeds %d byte total limit", src, lim.MaxTotalBytes)
			}
		case tar.TypeSymlink, tar.TypeLink:
			links.add(hdr.Name)
		default:
			// char/block/fifo/etc have no business in a package; skip
		}
	}
}

// fileBudget bounds one file's write to the smaller of the per-file cap and
// what remains of the total budget, so the on-disk total can never overshoot
// MaxTotalBytes by a stray MaxFileBytes.
func fileBudget(lim Limits, written int64) int64 {
	if rem := lim.MaxTotalBytes - written; rem < lim.MaxFileBytes {
		return rem
	}
	return lim.MaxFileBytes
}

// commonRoot returns the first path segment if every regular file and
// directory entry shares it, otherwise "". Skipping bodies still decompresses
// them, so the scan carries its own ceiling: an archive pass 2 would reject
// on size anyway aborts here instead of burning unbounded CPU first.
func commonRoot(src string, lim Limits) (string, error) {
	f, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", fmt.Errorf("%s: %w", src, err)
	}
	defer gz.Close()

	root := ""
	sawAny := false
	ceiling := lim.MaxTotalBytes + lim.MaxFileBytes
	cr := &countReader{r: gz}
	tr := tar.NewReader(cr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("%s: %w", src, err)
		}
		if cr.n > ceiling {
			return "", fmt.Errorf("%s: decompresses past %d bytes during the root scan; refusing (decompression bomb guard)", src, ceiling)
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeDir {
			continue
		}
		name, err := sanitize(hdr.Name)
		if err != nil || name == "" {
			continue // pass 2 records hostile names
		}
		seg, _, hasSlash := strings.Cut(name, "/")
		if hdr.Typeflag == tar.TypeReg && !hasSlash {
			return "", nil // top-level file: no common root
		}
		if !sawAny {
			root, sawAny = seg, true
		} else if seg != root {
			return "", nil
		}
	}
	return root, nil
}

// countReader counts decompressed bytes flowing through it.
type countReader struct {
	r io.Reader
	n int64
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// writeCapped writes at most max bytes (the per-file cap, or the remaining
// total budget when that is smaller) and errors past it.
func writeCapped(target string, r io.Reader, max int64) (int64, error) {
	f, err := os.Create(target)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	n, err := io.Copy(f, io.LimitReader(r, max+1))
	if err != nil {
		return n, err
	}
	if n > max {
		return n, fmt.Errorf("exceeds the %d byte extraction budget", max)
	}
	return n, nil
}

func sanitize(name string) (string, error) {
	for _, b := range []byte(name) {
		// control bytes in names are terminal-escape attacks on whoever
		// lists the tree; no legitimate package contains them
		if b < 0x20 || b == 0x7f {
			return "", fmt.Errorf("control byte 0x%02x in name", b)
		}
	}
	// Windows-shaped escapes: path.Clean is slash-only, so ..\evil and
	// \\unc\share would survive it and become separators on a Windows
	// filesystem. Colons are rejected in ANY position because prefix
	// stripping can promote an interior segment to the front (package/
	// c:evil -> c:evil, a drive-relative path on Windows), and NTFS
	// treats name:stream as an alternate data stream.
	if strings.ContainsRune(name, '\\') {
		return "", fmt.Errorf("backslash in name")
	}
	if strings.ContainsRune(name, ':') {
		return "", fmt.Errorf("colon in name (windows drive/ADS)")
	}
	clean := path.Clean(name)
	if path.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("escapes extraction root")
	}
	if clean == "." {
		return "", nil
	}
	return clean, nil
}
