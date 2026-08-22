// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package checkprocfs

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/cilium/tetragon/pkg/option"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestCheckMissingProcFS(t *testing.T) {
	oldProcFS := option.Config.ProcFS
	t.Cleanup(func() { option.Config.ProcFS = oldProcFS })
	option.Config.ProcFS = t.TempDir()

	err := Check()
	if err == nil || !strings.Contains(err.Error(), "stat host PID namespace") {
		t.Fatalf("Check() error = %v, want stat failure", err)
	}
	if got := testutil.ToFloat64(hostProcFSValid.WithLabelValues()); got != 0 {
		t.Fatalf("host_procfs_valid = %v, want 0", got)
	}
}

func TestCheckMismatchedPIDNamespace(t *testing.T) {
	oldProcFS := option.Config.ProcFS
	t.Cleanup(func() { option.Config.ProcFS = oldProcFS })
	option.Config.ProcFS = t.TempDir()

	nsDir := filepath.Join(option.Config.ProcFS, "1", "ns")
	if err := os.MkdirAll(nsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nsDir, "pid"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	err := Check()
	if err == nil || !strings.Contains(err.Error(), "does not expose the host PID namespace") {
		t.Fatalf("Check() error = %v, want inode mismatch", err)
	}
	if got := testutil.ToFloat64(hostProcFSValid.WithLabelValues()); got != 0 {
		t.Fatalf("host_procfs_valid = %v, want 0", got)
	}
}

func TestCheckHostPIDNamespace(t *testing.T) {
	err := check("/proc/1/ns/pid", func(_ string, stat *syscall.Stat_t) error {
		stat.Ino = hostPIDNamespaceInode
		return nil
	})
	if err != nil {
		t.Fatalf("check() error = %v, want nil", err)
	}
	if got := testutil.ToFloat64(hostProcFSValid.WithLabelValues()); got != 1 {
		t.Fatalf("host_procfs_valid = %v, want 1", got)
	}

	// Metrics are initialized after the startup check. Initialization must
	// retain the observed result instead of resetting the gauge to zero.
	hostProcFSValid.Init()
	if got := testutil.ToFloat64(hostProcFSValid.WithLabelValues()); got != 1 {
		t.Fatalf("host_procfs_valid after Init() = %v, want 1", got)
	}
}
