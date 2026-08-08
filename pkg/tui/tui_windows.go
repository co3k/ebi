//go:build windows

package tui

import (
	"os"
	"syscall"
)

func ignoreSignalsList() []os.Signal {
	return []os.Signal{syscall.SIGINT, syscall.SIGTERM}
}
