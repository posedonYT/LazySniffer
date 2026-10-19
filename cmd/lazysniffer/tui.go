package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"

	tea "charm.land/bubbletea/v2"

	"github.com/poseydon/lazysniffer/internal/config"
	"github.com/poseydon/lazysniffer/internal/keylog"
	"github.com/poseydon/lazysniffer/internal/lua"
	"github.com/poseydon/lazysniffer/internal/ui"
)

func runTUI(path string, f uiFlags) error {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "lazysniffer: %v (using defaults)\n", err)
	}
	setupKeylog(cfg, f.keylog)
	var luaErrs []error
	luaErrs = append(luaErrs, lua.LoadDir(filepath.Join(config.Dir(), "plugins"))...)
	for _, p := range f.lua {
		if err := lua.LoadFile(p); err != nil {
			luaErrs = append(luaErrs, fmt.Errorf("%s: %w", p, err))
		}
	}
	app := ui.New(cfg, ui.Options{LuaErrors: luaErrs, Path: path, Filter: f.filter, Ifaces: f.ifaces, CaptureFilter: f.captureFilter, SSH: f.ssh})
	_, err = tea.NewProgram(app).Run()
	return err
}

// setupKeylog registers TLS key log files: --keylog, $SSLKEYLOGFILE and the
// preference tls_keylog_file.
func setupKeylog(cfg *config.Config, flag string) {
	var files []string
	for _, p := range []string{flag, os.Getenv("SSLKEYLOGFILE"), cfg.TLSKeylogFile} {
		if p != "" && !slices.Contains(files, p) {
			files = append(files, p)
		}
	}
	keylog.Default.SetFiles(files...)
}
