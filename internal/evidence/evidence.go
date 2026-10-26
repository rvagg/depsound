// Package evidence exports bounded, inert dependency-review evidence.
package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/rvagg/depsound/internal/fetch"
	"github.com/rvagg/depsound/internal/manifest"
	"github.com/rvagg/depsound/internal/stats"
)

const (
	dataDir      = "data"
	manifestName = "manifest.json"
)

// Limits bounds an evidence export.
type Limits struct {
	MaxFiles         int   `json:"maxFiles"`
	MaxFileBytes     int64 `json:"maxFileBytes"`
	MaxTotalBytes    int64 `json:"maxTotalBytes"`
	MaxMetadataBytes int64 `json:"maxMetadataBytes"`
}

// DefaultLimits bounds exports while retaining enough evidence for review.
var DefaultLimits = Limits{
	MaxFiles:         10000,
	MaxFileBytes:     64 << 20,
	MaxTotalBytes:    256 << 20,
	MaxMetadataBytes: 16 << 20,
}

// Input describes one rendered report and its backing cache evidence.
type Input struct {
	Kind   string
	Report any
	Replay *manifest.ReviewPacket
	Items  []Item
}

// Item groups the sources belonging to one report item.
type Item struct {
	Ref       string
	Workspace string
	Sources   []Source
}

// Source identifies cache evidence for one endpoint.
type Source struct {
	Side        string
	Archive     string
	Extension   string
	Tree        string
	MetaFile    string
	ExtractFile string
	Metadata    *stats.Source
	Unavailable *stats.Unavailable
}

// Manifest describes every retained byte and every omission. Paths are always
// relative to the export directory.
type Manifest struct {
	Version             int         `json:"version"`
	Kind                string      `json:"kind"`
	Report              string      `json:"report"`
	ReportFile          File        `json:"reportFile"`
	ReplayFile          *File       `json:"replayFile,omitempty"`
	Limits              Limits      `json:"limits"`
	Notice              string      `json:"notice"`
	Files               []File      `json:"files,omitempty"`
	Sources             []Ownership `json:"sources,omitempty"`
	Omissions           []Omission  `json:"omissions,omitempty"`
	SuppressedOmissions int         `json:"suppressedOmissions,omitempty"`
}

// File records one byte file stored under data/.
type File struct {
	Path string `json:"path"`
	Role string `json:"role"`
	// Transform identifies bytes rewritten before retention.
	Transform      string `json:"transform,omitempty"`
	Bytes          int64  `json:"bytes"`
	SHA256         string `json:"sha256"`
	OriginalSHA256 string `json:"originalSha256,omitempty"`
}

// Ownership relates an item/source/path in the original inert tree to a copied
// byte file. DataPath may be shared by duplicate source references.
type Ownership struct {
	Ref              string             `json:"ref"`
	Side             string             `json:"side,omitempty"`
	Role             string             `json:"role"`
	Original         string             `json:"original,omitempty"`
	OriginalEncoding string             `json:"originalEncoding,omitempty"`
	DataPath         string             `json:"dataPath,omitempty"`
	Metadata         *stats.Source      `json:"metadata,omitempty"`
	Unavailable      *stats.Unavailable `json:"unavailable,omitempty"`
}

// Omission records evidence that was intentionally not retained.
type Omission struct {
	Ref              string `json:"ref,omitempty"`
	Side             string `json:"side,omitempty"`
	Role             string `json:"role"`
	Original         string `json:"original,omitempty"`
	OriginalEncoding string `json:"originalEncoding,omitempty"`
	Reason           string `json:"reason"`
}

type exporter struct {
	root              *os.Root
	sourceRoot        string
	output            *os.Root
	limits            Limits
	manifest          Manifest
	files             int
	visited           int
	bytes             int64
	rootMetadataBytes int64
	sequence          int
	copied            map[string]string
}

// Export writes an inert evidence directory. destination must not exist and
// must not be within cacheRoot. A failed export never has a manifest.json.
func Export(cacheRoot, destination string, input Input, limits Limits) (*Manifest, error) {
	if err := validLimits(limits); err != nil {
		return nil, err
	}
	cacheAbsolute, err := filepath.Abs(cacheRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve cache root: %w", err)
	}
	rootPath, err := filepath.EvalSymlinks(cacheAbsolute)
	if err != nil {
		return nil, fmt.Errorf("open cache root: %w", err)
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, fmt.Errorf("open cache root: %w", err)
	}
	defer root.Close()

	dest, err := resolvedDestination(destination)
	if err != nil {
		return nil, err
	}
	if within(rootPath, dest) {
		return nil, errors.New("evidence destination is within cache root")
	}
	if _, err := os.Lstat(dest); err == nil {
		return nil, fmt.Errorf("evidence destination already exists: %s", dest)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("inspect evidence destination: %w", err)
	}
	if err := os.Mkdir(dest, 0o700); err != nil {
		return nil, fmt.Errorf("create evidence destination: %w", err)
	}
	output, err := os.OpenRoot(dest)
	if err != nil {
		return nil, fmt.Errorf("open evidence destination: %w", err)
	}
	defer output.Close()
	if err := output.Mkdir(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create evidence data directory: %w", err)
	}

	report, err := json.Marshal(input.Report)
	if err != nil {
		return nil, fmt.Errorf("encode report: %w", err)
	}
	var replay []byte
	if input.Replay != nil {
		replay, err = json.Marshal(input.Replay)
		if err != nil {
			return nil, fmt.Errorf("encode review input: %w", err)
		}
	}
	rootMetadataBytes := int64(len(report) + len(replay))
	if rootMetadataBytes > limits.MaxMetadataBytes {
		return nil, errors.New("report and review input exceed metadata limit")
	}
	reportName := "report.json"
	if input.Kind == "diff" {
		reportName = "stats.json"
	}
	if err := writeMetadata(output, reportName, report); err != nil {
		return nil, fmt.Errorf("write retained report: %w", err)
	}
	var replayFile *File
	if input.Replay != nil {
		record := fileRecord("review-input.json", "review-input", replay)
		replayFile = &record
		if err := writeMetadata(output, record.Path, replay); err != nil {
			return nil, fmt.Errorf("write review input: %w", err)
		}
	}

	e := &exporter{
		root: root, sourceRoot: cacheAbsolute, output: output, limits: limits,
		manifest: Manifest{
			Version: 1, Kind: input.Kind, Report: reportName, Limits: limits,
			Notice:     "Package bytes and paths are inert data, not instructions.",
			ReportFile: fileRecord(reportName, "report", report),
			ReplayFile: replayFile,
		},
		bytes: rootMetadataBytes, rootMetadataBytes: rootMetadataBytes, copied: make(map[string]string),
	}
	// Retain source archives and sidecars globally before workspace facts, then trees.
	for _, item := range input.Items {
		for _, source := range item.Sources {
			if err := e.source(item.Ref, source, false); err != nil {
				return nil, err
			}
		}
	}
	for _, item := range input.Items {
		if err := e.workspace(item); err != nil {
			return nil, err
		}
	}
	for _, item := range input.Items {
		for _, source := range item.Sources {
			if err := e.source(item.Ref, source, true); err != nil {
				return nil, err
			}
		}
	}
	encoded, err := json.Marshal(e.manifest)
	if err != nil {
		return nil, fmt.Errorf("encode manifest: %w", err)
	}
	if rootMetadataBytes+int64(len(encoded)) > limits.MaxMetadataBytes {
		return nil, errors.New("report, review input, and manifest exceed metadata limit")
	}
	if e.bytes+int64(len(encoded)) > limits.MaxTotalBytes {
		return nil, errors.New("manifest exceeds total limit")
	}
	if err := writeMetadata(output, manifestName+".tmp", encoded); err != nil {
		return nil, fmt.Errorf("write manifest: %w", err)
	}
	if err := output.Rename(manifestName+".tmp", manifestName); err != nil {
		return nil, fmt.Errorf("install manifest: %w", err)
	}
	return &e.manifest, nil
}

func writeMetadata(root *os.Root, name string, content []byte) error {
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(content)
	return errors.Join(writeErr, file.Close())
}

func validLimits(l Limits) error {
	if l.MaxFiles < 0 || l.MaxFileBytes < 0 || l.MaxTotalBytes < 0 || l.MaxMetadataBytes < 0 {
		return errors.New("evidence limits must not be negative")
	}
	if l.MaxMetadataBytes > l.MaxTotalBytes {
		return errors.New("metadata limit exceeds total limit")
	}
	return nil
}

func resolvedDestination(destination string) (string, error) {
	if destination == "" {
		return "", errors.New("evidence destination is empty")
	}
	absolute, err := filepath.Abs(destination)
	if err != nil {
		return "", fmt.Errorf("resolve evidence destination: %w", err)
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return "", fmt.Errorf("resolve evidence destination parent: %w", err)
	}
	return filepath.Join(parent, filepath.Base(absolute)), nil
}

func within(root, name string) bool {
	rel, err := filepath.Rel(root, name)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func (e *exporter) workspace(item Item) error {
	for _, name := range []string{"stats.json", "diff.patch", "surface.json"} {
		if item.Workspace == "" {
			continue
		}
		if err := e.copy(item.Ref, "", "workspace", filepath.Join(item.Workspace, name), name, ""); err != nil {
			return err
		}
	}
	return nil
}

func (e *exporter) source(ref string, source Source, trees bool) error {
	if !trees && (source.Metadata != nil || source.Unavailable != nil) {
		e.manifest.Sources = append(e.manifest.Sources, Ownership{Ref: ref, Side: source.Side, Role: "source", Metadata: source.Metadata, Unavailable: source.Unavailable})
	}
	if trees {
		if source.Tree != "" {
			return e.tree(ref, source)
		}
		return nil
	}
	for _, candidate := range []struct{ role, file, extension string }{
		{"archive", source.Archive, source.Extension},
		{"sidecar", source.MetaFile, ""},
		{"extract", source.ExtractFile, ""},
	} {
		if candidate.file == "" {
			continue
		}
		if candidate.role == "archive" && !archiveExtension(candidate.extension) {
			e.omit(ref, source.Side, candidate.role, "", "invalid archive extension")
			continue
		}
		if err := e.copy(ref, source.Side, candidate.role, candidate.file, "", candidate.extension); err != nil {
			return err
		}
	}
	return nil
}

func (e *exporter) tree(ref string, source Source) error {
	rel, err := e.confined(source.Tree)
	if err != nil {
		e.omit(ref, source.Side, "tree", "", err.Error())
		return nil
	}
	info, err := e.root.Lstat(rel)
	if err != nil {
		e.omit(ref, source.Side, "tree", "", "unreadable: "+err.Error())
		return nil
	}
	if !info.IsDir() {
		e.omit(ref, source.Side, "tree", "", "not a directory")
		return nil
	}
	return e.treeDir(ref, source, rel, "")
}

func (e *exporter) treeDir(ref string, source Source, directory, original string) error {
	remaining := e.limits.MaxFiles - e.visited
	if remaining <= 0 {
		e.omit(ref, source.Side, "tree", original, "entry limit reached; subtree unvisited")
		return nil
	}
	dir, err := e.root.Open(directory)
	if err != nil {
		e.omit(ref, source.Side, "tree", original, "unreadable: "+err.Error())
		return nil
	}
	defer dir.Close()
	entries, err := dir.ReadDir(remaining + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		e.omit(ref, source.Side, "tree", original, "unreadable: "+err.Error())
		return nil
	}
	e.visited += len(entries)
	if len(entries) > remaining {
		e.omit(ref, source.Side, "tree", original, "directory entry limit exceeded; subtree unvisited")
		return nil
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		// Directory entries are reserved before descent, bounding pending slices.
		entryOriginal := entry.Name()
		if original != "" {
			entryOriginal = path.Join(original, entry.Name())
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			e.omit(ref, source.Side, "tree", entryOriginal, "symlink skipped")
			continue
		}
		if entry.IsDir() {
			if err := e.treeDir(ref, source, path.Join(directory, entry.Name()), entryOriginal); err != nil {
				return err
			}
			continue
		}
		if !entry.Type().IsRegular() {
			e.omit(ref, source.Side, "tree", entryOriginal, "special file skipped")
			continue
		}
		if err := e.copy(ref, source.Side, "tree", filepath.Join(source.Tree, filepath.FromSlash(entryOriginal)), entryOriginal, ""); err != nil {
			return err
		}
	}
	return nil
}

func (e *exporter) copy(ref, side, role, source, original, extension string) error {
	rel, err := e.confined(source)
	if err != nil {
		e.omit(ref, side, role, original, err.Error())
		return nil
	}
	if role == "sidecar" {
		return e.copyMetadata(ref, side, role, source, original, rel, "structured-url-redaction", sanitizeFetchMeta)
	}
	if role == "workspace" && filepath.Base(source) == "stats.json" {
		return e.copyMetadata(ref, side, role, source, original, rel, "structured-url-redaction", sanitizeStats)
	}
	if existing, ok := e.copied[rel]; ok {
		e.retained(ref, side, role, original, existing)
		return nil
	}
	info, err := e.root.Lstat(rel)
	if err != nil {
		e.omit(ref, side, role, original, "missing: "+err.Error())
		return nil
	}
	if !info.Mode().IsRegular() {
		e.omit(ref, side, role, original, "not a regular file")
		return nil
	}
	if e.files >= e.limits.MaxFiles {
		e.omit(ref, side, role, original, "file limit reached")
		return nil
	}
	if info.Size() > e.limits.MaxFileBytes {
		e.omit(ref, side, role, original, "file size limit exceeded")
		return nil
	}
	remaining := e.limits.MaxTotalBytes - e.bytes - (e.limits.MaxMetadataBytes - e.rootMetadataBytes)
	if info.Size() > remaining {
		e.omit(ref, side, role, original, "total size limit exceeded")
		return nil
	}
	in, err := e.root.Open(rel)
	if err != nil {
		e.omit(ref, side, role, original, "unreadable: "+err.Error())
		return nil
	}
	defer in.Close()
	opened, err := in.Stat()
	if err != nil || !opened.Mode().IsRegular() {
		e.omit(ref, side, role, original, "not a regular file")
		return nil
	}
	e.sequence++
	dataPath := filepath.ToSlash(filepath.Join(dataDir, fmt.Sprintf("%08d.data", e.sequence)))
	if role == "archive" && extension != "" {
		dataPath = strings.TrimSuffix(dataPath, ".data") + extension
	}
	out, err := e.output.OpenFile(dataPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create evidence data file: %w", err)
	}
	h := sha256.New()
	copyLimit := min(info.Size(), e.limits.MaxFileBytes, remaining)
	written, copyErr := io.Copy(io.MultiWriter(out, h), io.LimitReader(in, copyLimit+1))
	closeErr := out.Close()
	if copyErr != nil || closeErr != nil {
		_ = e.output.Remove(dataPath)
		return fmt.Errorf("write evidence data file: %w", errors.Join(copyErr, closeErr))
	}
	if written > copyLimit || written != info.Size() {
		_ = e.output.Remove(dataPath)
		e.sequence--
		e.omit(ref, side, role, original, "changed while copying")
		return nil
	}
	e.files++
	e.bytes += written
	e.copied[rel] = dataPath
	e.manifest.Files = append(e.manifest.Files, File{Path: dataPath, Role: role, Bytes: written, SHA256: hex.EncodeToString(h.Sum(nil))})
	e.retained(ref, side, role, original, dataPath)
	return nil
}

func sanitizeFetchMeta(raw []byte) ([]byte, error) {
	if err := metadataObject(raw); err != nil {
		return nil, err
	}
	var meta fetch.Meta
	if err := json.Unmarshal(raw, &meta); err != nil {
		return nil, err
	}
	return json.Marshal(meta)
}

func sanitizeStats(raw []byte) ([]byte, error) {
	if err := metadataObject(raw); err != nil {
		return nil, err
	}
	var report stats.Stats
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, err
	}
	return json.Marshal(report)
}

func metadataObject(raw []byte) error {
	if trimmed := bytes.TrimSpace(raw); len(trimmed) == 0 || trimmed[0] != '{' {
		return errors.New("metadata must be a JSON object")
	}
	return nil
}

func (e *exporter) copyMetadata(ref, side, role, source, original, rel, transform string, sanitize func([]byte) ([]byte, error)) error {
	if existing, ok := e.copied[rel]; ok {
		e.retained(ref, side, role, original, existing)
		return nil
	}
	info, err := e.root.Lstat(rel)
	if err != nil {
		e.omit(ref, side, role, original, "missing: "+err.Error())
		return nil
	}
	if !info.Mode().IsRegular() {
		e.omit(ref, side, role, original, "not a regular file")
		return nil
	}
	if e.files >= e.limits.MaxFiles {
		e.omit(ref, side, role, original, "file limit reached")
		return nil
	}
	if info.Size() > e.limits.MaxFileBytes {
		e.omit(ref, side, role, original, "file size limit exceeded")
		return nil
	}
	in, err := e.root.Open(rel)
	if err != nil {
		e.omit(ref, side, role, original, "unreadable: "+err.Error())
		return nil
	}
	defer in.Close()
	opened, err := in.Stat()
	if err != nil || !opened.Mode().IsRegular() {
		e.omit(ref, side, role, original, "not a regular file")
		return nil
	}
	raw, err := io.ReadAll(io.LimitReader(in, e.limits.MaxFileBytes+1))
	if err != nil {
		e.omit(ref, side, role, original, "unreadable: "+err.Error())
		return nil
	}
	if int64(len(raw)) > e.limits.MaxFileBytes || int64(len(raw)) != info.Size() {
		e.omit(ref, side, role, original, "changed while reading metadata")
		return nil
	}
	content, err := sanitize(raw)
	if err != nil {
		e.omit(ref, side, role, original, "invalid metadata: "+err.Error())
		return nil
	}
	if int64(len(content)) > e.limits.MaxFileBytes {
		e.omit(ref, side, role, original, "sanitized metadata exceeds file size limit")
		return nil
	}
	remaining := e.limits.MaxTotalBytes - e.bytes - (e.limits.MaxMetadataBytes - e.rootMetadataBytes)
	if int64(len(content)) > remaining {
		e.omit(ref, side, role, original, "total size limit exceeded")
		return nil
	}
	e.sequence++
	dataPath := filepath.ToSlash(filepath.Join(dataDir, fmt.Sprintf("%08d.data", e.sequence)))
	out, err := e.output.OpenFile(dataPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create evidence data file: %w", err)
	}
	_, writeErr := out.Write(content)
	closeErr := out.Close()
	if writeErr != nil || closeErr != nil {
		_ = e.output.Remove(dataPath)
		return fmt.Errorf("write evidence data file: %w", errors.Join(writeErr, closeErr))
	}
	e.files++
	e.bytes += int64(len(content))
	e.copied[rel] = dataPath
	record := fileRecord(dataPath, role, content)
	record.Transform = transform
	originalDigest := sha256.Sum256(raw)
	record.OriginalSHA256 = hex.EncodeToString(originalDigest[:])
	e.manifest.Files = append(e.manifest.Files, record)
	e.retained(ref, side, role, original, dataPath)
	return nil
}

func fileRecord(name, role string, content []byte) File {
	sum := sha256.Sum256(content)
	return File{Path: name, Role: role, Bytes: int64(len(content)), SHA256: hex.EncodeToString(sum[:])}
}

func (e *exporter) confined(name string) (string, error) {
	absolute, err := filepath.Abs(name)
	if err != nil {
		return "", err
	}
	// Cache inputs can use the caller's root alias or its canonical path.
	root := e.sourceRoot
	if !within(root, absolute) {
		root = e.root.Name()
	}
	rel, err := filepath.Rel(root, absolute)
	if err != nil || !within(root, absolute) {
		return "", errors.New("path is outside cache root")
	}
	rel = filepath.ToSlash(rel)
	for i := 0; i <= len(rel); i++ {
		if i < len(rel) && rel[i] != '/' {
			continue
		}
		info, err := e.root.Lstat(rel[:i])
		if err != nil {
			return "", err
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			return "", errors.New("source path contains symlink")
		}
	}
	return filepath.ToSlash(rel), nil
}

func originalPath(original string) (string, string) {
	for remaining := original; remaining != ""; {
		r, size := utf8.DecodeRuneInString(remaining)
		if r == utf8.RuneError && size == 1 || unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) {
			return base64.StdEncoding.EncodeToString([]byte(original)), "base64"
		}
		remaining = remaining[size:]
	}
	return original, ""
}

func (e *exporter) retained(ref, side, role, original, dataPath string) {
	original, encoding := originalPath(original)
	e.manifest.Sources = append(e.manifest.Sources, Ownership{
		Ref: ref, Side: side, Role: role, Original: original,
		OriginalEncoding: encoding, DataPath: dataPath,
	})
}

func (e *exporter) omit(ref, side, role, original, reason string) {
	if len(e.manifest.Omissions) >= e.limits.MaxFiles+16 {
		e.manifest.SuppressedOmissions++
		return
	}
	original, encoding := originalPath(original)
	e.manifest.Omissions = append(e.manifest.Omissions, Omission{
		Ref: ref, Side: side, Role: role, Original: original,
		OriginalEncoding: encoding, Reason: reason,
	})
}

func archiveExtension(extension string) bool {
	switch extension {
	case "", ".tgz", ".zip", ".crate", ".tar.gz":
		return true
	default:
		return false
	}
}
