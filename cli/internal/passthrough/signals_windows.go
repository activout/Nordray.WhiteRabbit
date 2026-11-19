//go:build windows

package passthrough

import (
	"os"
	"os/exec"
)

func forwardedSignals() []os.Signal { return []os.Signal{os.Interrupt} }

func exitCode(e *exec.ExitError) int { return e.ExitCode() }
