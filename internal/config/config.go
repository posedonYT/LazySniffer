// Package config loads and saves user settings: preferences, recent files,
// filter history and bookmarks, column layout and coloring rules.
package config

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"gopkg.in/yaml.v3"
)

// SavedFilter is a display filter bookmark.
type SavedFilter struct {
	Name   string `yaml:"name"`
	Filter string `yaml:"filter"`
}

// Config is the persisted user configuration.
type Config struct {
	Theme          string        `yaml:"theme"` // auto, dark, light
	TimeFormat     string        `yaml:"time_format"`
	TimePrecision  int           `yaml:"time_precision"`
	ColorRows      bool          `yaml:"color_rows"`
	ColorStyle     string        `yaml:"color_style"` // background or foreground
	ResolveMAC     bool          `yaml:"resolve_mac"`
	ResolveNetwork bool          `yaml:"resolve_network"`
	ResolvePorts   bool          `yaml:"resolve_ports"`
	Mouse          bool          `yaml:"mouse"`
	ShowProcess    bool          `yaml:"show_process_column"`
	CaptureFilter  string        `yaml:"capture_filter,omitempty"`
	LastSSH        string        `yaml:"last_ssh,omitempty"`
	TLSKeylogFile  string        `yaml:"tls_keylog_file,omitempty"`
	GeoIPDir       string        `yaml:"geoip_dir,omitempty"`
	Columns        []ColumnSpec  `yaml:"columns,omitempty"`
	RecentFiles    []string      `yaml:"recent_files,omitempty"`
	FilterHistory  []string      `yaml:"filter_history,omitempty"`
	SavedFilters   []SavedFilter `yaml:"saved_filters,omitempty"`
	FilterButtons  []SavedFilter `yaml:"filter_buttons,omitempty"`
	// DecodeAs lists user overrides of port → protocol (Analyze → Decode As).
	DecodeAs []DecodeAsEntry `yaml:"decode_as,omitempty"`
	// DisabledProtocols are protocols (filter names) turned off in Enabled Protocols.
	DisabledProtocols []string `yaml:"disabled_protocols,omitempty"`
	// Keys overrides default key bindings: action id -> keys.
	Keys map[string][]string `yaml:"keys,omitempty"`

	path string
}

// DecodeAsEntry maps a table key to a dissector handle.
type DecodeAsEntry struct {
	Table  string `yaml:"table"` // tcp.port, udp.port, ethertype, ip.proto…
	Value  uint64 `yaml:"value"`
	Handle string `yaml:"handle"`
}

// ColumnSpec is a user-defined packet list column.
type ColumnSpec struct {
	Title string `yaml:"title"`
	Type  string `yaml:"type"`
	Field string `yaml:"field,omitempty"`
	Width int    `yaml:"width,omitempty"`
	Hide  bool   `yaml:"hidden,omitempty"`
}

// Defaults returns the configuration used when no file exists.
func Defaults() *Config {
	return &Config{
		Theme:         "auto",
		TimeFormat:    "relative",
		TimePrecision: 6,
		ColorRows:     true,
		ColorStyle:    "background",
		ResolveMAC:    true,
		ResolvePorts:  false,
		Mouse:         true,
		SavedFilters: []SavedFilter{
			{Name: "TCP problems", Filter: "tcp.analysis.flags && !tcp.analysis.window_update"},
			{Name: "TCP handshakes", Filter: "tcp.flags.syn == 1"},
			{Name: "Resets", Filter: "tcp.flags.reset == 1"},
			{Name: "DNS", Filter: "dns"},
			{Name: "TLS Client Hello", Filter: "tls.handshake.type == 1"},
			{Name: "HTTP requests", Filter: "http.request"},
			{Name: "Not ARP/DNS/mDNS", Filter: "!arp && !dns && !mdns"},
			{Name: "Errors and warnings", Filter: "_ws.expert.severity >= 4"},
		},
	}
}

// Profile is the active configuration profile ("" = the default one).
var Profile string

// BaseDir is the configuration directory without the profile.
func BaseDir() string {
	if d := os.Getenv("LAZYSNIFFER_CONFIG_DIR"); d != "" {
		return d
	}
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "lazysniffer")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "lazysniffer")
	}
	return filepath.Join(home, ".config", "lazysniffer")
}

// Dir returns the directory of the active profile.
func Dir() string {
	if Profile != "" {
		return filepath.Join(BaseDir(), "profiles", Profile)
	}
	return BaseDir()
}

// Profiles lists the available configuration profiles.
func Profiles() []string {
	ents, _ := os.ReadDir(filepath.Join(BaseDir(), "profiles"))
	out := []string{"Default"}
	for _, e := range ents {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	return out
}

// Load reads config.yml, falling back to defaults.
func Load() (*Config, error) {
	c := Defaults()
	c.path = filepath.Join(Dir(), "config.yml")
	b, err := os.ReadFile(c.path)
	if errors.Is(err, fs.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	if err := yaml.Unmarshal(b, c); err != nil {
		return Defaults(), err
	}
	return c, nil
}

// Path is where the configuration is stored.
func (c *Config) Path() string { return c.path }

// Save writes the configuration atomically.
func (c *Config) Save() error {
	if c.path == "" {
		c.path = filepath.Join(Dir(), "config.yml")
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o755); err != nil {
		return err
	}
	b, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}

// AddRecent records an opened file (most recent first, max 15).
func (c *Config) AddRecent(path string) {
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	c.RecentFiles = slices.DeleteFunc(c.RecentFiles, func(s string) bool { return s == path })
	c.RecentFiles = append([]string{path}, c.RecentFiles...)
	if len(c.RecentFiles) > 15 {
		c.RecentFiles = c.RecentFiles[:15]
	}
}

// AddFilterHistory records an applied display filter (max 50).
func (c *Config) AddFilterHistory(f string) {
	if f == "" {
		return
	}
	c.FilterHistory = slices.DeleteFunc(c.FilterHistory, func(s string) bool { return s == f })
	c.FilterHistory = append([]string{f}, c.FilterHistory...)
	if len(c.FilterHistory) > 50 {
		c.FilterHistory = c.FilterHistory[:50]
	}
}
