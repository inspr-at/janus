// Package versioninfo owns the explicit release coordinate and offline presentation.
package versioninfo

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"regexp"
	"strings"
	"time"
)

const Scheme = "inspr-calendar-v2"
const PresentationRevision = "317f872bc061576fc0b45d274d3a22f69bcd4c8a"
const ConfigSHA256 = "7843f3515ce329277d2d576000bd60ac410d725b241d502a9a3fecb2533d956d"
const ManifestSHA256 = "b1125b92bf8c0bb0a9e14968924230f04503d226b63d0a0aee544efbdaf00af2"

//go:embed release.json all:presentation
var assets embed.FS

type Channel struct {
	TagPrefix       string `json:"tag_prefix"`
	ReleaseSequence uint64 `json:"release_sequence"`
	Migration       struct {
		LegacyScheme                 string `json:"legacy_scheme"`
		LastLegacyVersion            string `json:"last_legacy_version"`
		LastLegacyCommit             string `json:"last_legacy_commit"`
		FirstCalendarVersion         string `json:"first_calendar_version"`
		FirstCalendarReleaseSequence uint64 `json:"first_calendar_release_sequence"`
	} `json:"migration"`
}
type Release struct {
	Schema     string             `json:"schema"`
	Scheme     string             `json:"version_scheme"`
	Version    string             `json:"version"`
	ReservedAt string             `json:"reserved_at"`
	Owner      string             `json:"owner"`
	Channels   map[string]Channel `json:"channels"`
}

var coordinatePattern = regexp.MustCompile(`^[1-9][0-9]{11}\.0\.0$`)
var Current = mustLoad()

func mustLoad() Release {
	var value Release
	raw, err := assets.ReadFile("release.json")
	if err == nil {
		err = json.Unmarshal(raw, &value)
	}
	if err == nil {
		err = Validate(value)
	}
	if err == nil {
		err = VerifyPresentation(assets)
	}
	if err != nil {
		panic("Janus release metadata or pinned presentation is invalid")
	}
	return value
}
func Calendar(value, scheme string) (time.Time, error) {
	if scheme != Scheme || !coordinatePattern.MatchString(value) {
		return time.Time{}, fmt.Errorf("invalid calendar coordinate or scheme")
	}
	stamp, err := time.Parse("20060102150405", "20"+value[:12])
	if err != nil || stamp.Format("060102150405") != value[:12] {
		return time.Time{}, fmt.Errorf("invalid UTC calendar date")
	}
	return stamp, nil
}
func Validate(value Release) error {
	stamp, err := Calendar(value.Version, value.Scheme)
	if err != nil || value.Schema != "inspr.janus.release.v1" || value.Owner != "JANUS-471" || stamp.Format(time.RFC3339) != value.ReservedAt {
		return fmt.Errorf("invalid release source")
	}
	if len(value.Channels) != 2 {
		return fmt.Errorf("invalid release channels")
	}
	for name, prefix := range map[string]string{"stable": "rust-engine-v", "envelope-stable": "go-envelope-v"} {
		c := value.Channels[name]
		first, err := Calendar(c.Migration.FirstCalendarVersion, value.Scheme)
		if err != nil || c.TagPrefix != prefix || c.ReleaseSequence < c.Migration.FirstCalendarReleaseSequence || (value.Version == c.Migration.FirstCalendarVersion) != (c.ReleaseSequence == c.Migration.FirstCalendarReleaseSequence) || c.Migration.FirstCalendarReleaseSequence != 1 || c.Migration.LegacyScheme != "legacy" || stamp.Before(first) || !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(c.Migration.LastLegacyCommit) {
			return fmt.Errorf("invalid migration anchor")
		}
	}
	return nil
}
func digest(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }

// VerifyPresentation rejects incomplete, extra, altered and nonregular payloads.
// The expected digests are reviewed source constants, not derived from the candidate.
func VerifyPresentation(root fs.FS) error {
	raw, err := fs.ReadFile(root, "presentation/manifest.json")
	if err != nil || digest(raw) != ManifestSHA256 {
		return fmt.Errorf("presentation manifest mismatch")
	}
	var m struct {
		Repository string `json:"repository"`
		Revision   string `json:"revision"`
		Config     string `json:"expectedConfigSha256"`
		Schema     string `json:"schema"`
		Mode       string `json:"mode"`
		Runtime    bool   `json:"runtimeConsumers"`
		Files      []struct {
			Path string `json:"outputPath"`
			SHA  string `json:"sha256"`
			Size int    `json:"size"`
		} `json:"files"`
	}
	if json.Unmarshal(raw, &m) != nil || m.Repository != "inspr-at/inspr" || m.Revision != PresentationRevision || m.Config != ConfigSHA256 || m.Schema != "inspr.calendar-version-display.v2" || m.Mode != "build-time-only" || m.Runtime || len(m.Files) != 8 {
		return fmt.Errorf("presentation pin mismatch")
	}
	expected := map[string]bool{"manifest.json": true}
	for _, f := range m.Files {
		if f.Path == "" || strings.ContainsAny(f.Path, `/\`) || expected[f.Path] {
			return fmt.Errorf("invalid presentation path")
		}
		expected[f.Path] = true
		data, err := fs.ReadFile(root, "presentation/"+f.Path)
		if err != nil || len(data) != f.Size || digest(data) != f.SHA {
			return fmt.Errorf("presentation payload mismatch")
		}
	}
	entries, err := fs.ReadDir(root, "presentation")
	if err != nil || len(entries) != len(expected) {
		return fmt.Errorf("presentation file set mismatch")
	}
	for _, item := range entries {
		info, err := item.Info()
		if err != nil || !info.Mode().IsRegular() || !expected[item.Name()] {
			return fmt.Errorf("presentation must contain only pinned regular files")
		}
	}
	return nil
}
func Asset(name string) ([]byte, string, bool) {
	switch name {
	case "display.json", "schemes.json":
		raw, err := assets.ReadFile("presentation/" + name)
		return raw, "application/json; charset=utf-8", err == nil
	case "version.js", "presentation.js", "version-interaction.js", "auto-animate.js", "auto-animate-license.js":
		raw, err := assets.ReadFile("presentation/" + name)
		return raw, "text/javascript; charset=utf-8", err == nil
	}
	return nil, "", false
}
