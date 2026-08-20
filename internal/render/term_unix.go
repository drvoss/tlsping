//go:build unix

package render

import (
	"os"
	"syscall"
	"unsafe"
)

type winsize struct{ row, col, xpixel, ypixel uint16 }

func termWidth(f *os.File) int {
	var ws winsize
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		f.Fd(),
		uintptr(syscall.TIOCGWINSZ),
		uintptr(unsafe.Pointer(&ws)),
	)
	if errno != 0 {
		return 0
	}
	return int(ws.col)
}

func isTerminal(f *os.File) bool {
	return termWidth(f) > 0
}

// enableVT is a no-op: unix terminals handle ANSI natively.
func enableVT(*os.File) bool { return true }
