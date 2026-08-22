// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package checkprocfs

import (
	"fmt"
	"path/filepath"
	"sync/atomic"
	"syscall"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/cilium/tetragon/pkg/option"
)

const hostPIDNamespaceInode = uint64(0xEFFFFFFC)

var (
	hostProcFSValidState atomic.Int32
	hostProcFSValid      = metrics.MustNewGauge(metrics.NewOpts(
		consts.MetricsNamespace, "", "host_procfs_valid",
		"Whether the configured procfs exposes the host PID namespace (1 for valid, 0 for invalid).",
		nil, nil, nil,
	), func(metric *prometheus.GaugeVec) {
		metric.WithLabelValues().Set(float64(hostProcFSValidState.Load()))
	})
)

// RegisterMetrics registers procfs prerequisite health metrics.
func RegisterMetrics(group metrics.Group) {
	group.MustRegister(hostProcFSValid)
}

// Check determines whether the configured procfs exposes the host PID
// namespace. A failure can prevent process metadata from being attributed to
// tracing events.
func Check() error {
	path := filepath.Join(option.Config.ProcFS, "1", "ns", "pid")
	return check(path, syscall.Stat)
}

func check(path string, statFn func(string, *syscall.Stat_t) error) error {
	var stat syscall.Stat_t
	if err := statFn(path, &stat); err != nil {
		hostProcFSValidState.Store(0)
		hostProcFSValid.WithLabelValues().Set(0)
		return fmt.Errorf("stat host PID namespace %q: %w", path, err)
	}

	// we compare against the known inode of the host pid namespace:
	// ...
	// 	PROC_PID_INIT_INO	= 0xEFFFFFFCU,
	// ...
	if stat.Ino != hostPIDNamespaceInode {
		hostProcFSValidState.Store(0)
		hostProcFSValid.WithLabelValues().Set(0)
		return fmt.Errorf("procfs %q does not expose the host PID namespace: inode %d, expected %d", path, stat.Ino, hostPIDNamespaceInode)
	}

	hostProcFSValidState.Store(1)
	hostProcFSValid.WithLabelValues().Set(1)
	return nil
}
