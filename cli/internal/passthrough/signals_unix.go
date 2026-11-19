//go:build !windows

package passthrough

import (
	"os"
	"os/exec"
	"syscall"
)

func forwardedSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT}
}

// exitCode follows the shell convention: 128 + signal number when the child was killed by a signal.
func exitCode(e *exec.ExitError) int {
	if status, ok := e.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		return 128 + int(status.Signal())
	}
	return e.ExitCode()
}
