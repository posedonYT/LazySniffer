package capture

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

const (
	darwinScript = "/Library/Application Support/lazysniffer/ChmodBPF"
	darwinPlist  = "/Library/LaunchDaemons/com.lazysniffer.ChmodBPF.plist"
	linuxHelper  = "/usr/local/bin/lazysniffer-dumpcap"
)

const chmodBPF = `#!/bin/sh
# Installed by "lazysniffer setup": give the access_bpf group read/write
# access to the BPF devices so members can capture without sudo.
chgrp access_bpf /dev/bpf*
chmod g+rw /dev/bpf*
`

const launchPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key><string>com.lazysniffer.ChmodBPF</string>
	<key>ProgramArguments</key><array><string>/Library/Application Support/lazysniffer/ChmodBPF</string></array>
	<key>RunAtLoad</key><true/>
</dict>
</plist>
`

// Setup grants the invoking user capture permissions. It must run as root
// and is only ever started explicitly by the user (`sudo lazysniffer setup`).
func Setup(w io.Writer, uninstall bool) error {
	if os.Geteuid() != 0 {
		return errors.New("setup changes system permissions and must be run with sudo: sudo lazysniffer setup")
	}
	run := func(name string, args ...string) error {
		fmt.Fprintf(w, "+ %s %v\n", name, args)
		cmd := exec.Command(name, args...)
		cmd.Stdout, cmd.Stderr = w, w
		return cmd.Run()
	}
	switch runtime.GOOS {
	case "darwin":
		if uninstall {
			run("launchctl", "unload", darwinPlist)
			os.Remove(darwinPlist)
			os.Remove(darwinScript)
			fmt.Fprintln(w, "Removed the BPF permissions daemon. Run `sudo dseditgroup -o delete access_bpf` to drop the group.")
			return nil
		}
		user := os.Getenv("SUDO_USER")
		if user == "" {
			return errors.New("run setup through sudo so the invoking user can be added to access_bpf")
		}
		if exec.Command("dscl", ".", "-read", "/Groups/access_bpf").Run() != nil {
			if err := run("dseditgroup", "-o", "create", "access_bpf"); err != nil {
				return err
			}
		}
		if err := run("dseditgroup", "-o", "edit", "-a", user, "-t", "user", "access_bpf"); err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(darwinScript), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(darwinScript, []byte(chmodBPF), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(darwinPlist, []byte(launchPlist), 0o644); err != nil {
			return err
		}
		run("launchctl", "unload", darwinPlist)
		if err := run("launchctl", "load", "-w", darwinPlist); err != nil {
			return err
		}
		fmt.Fprintf(w, "\nDone. %s can capture without sudo after logging out and back in (new group membership).\n", user)
		return nil
	case "linux":
		if uninstall {
			os.Remove(linuxHelper)
			fmt.Fprintln(w, "Removed", linuxHelper)
			return nil
		}
		self, err := os.Executable()
		if err != nil {
			return err
		}
		in, err := os.ReadFile(self)
		if err != nil {
			return err
		}
		if err := os.WriteFile(linuxHelper, in, 0o755); err != nil {
			return err
		}
		if err := run("setcap", "cap_net_raw,cap_net_admin=eip", linuxHelper); err != nil {
			return fmt.Errorf("setcap failed (install libcap2-bin): %w", err)
		}
		fmt.Fprintf(w, "\nDone. lazysniffer will use %s to capture without sudo.\n", linuxHelper)
		return nil
	}
	return fmt.Errorf("setup is not supported on %s", runtime.GOOS)
}
