package render

import (
	"os"
	"strconv"
)

// Layout is the table shape chosen from the terminal width (PLAN §2.2).
type Layout uint8

const (
	// LayoutWide is the two-column table.
	LayoutWide Layout = iota
	// LayoutMid stacks one round over two lines.
	LayoutMid
	// LayoutMin prints the cold block, then the warm block.
	LayoutMin
)

// Width thresholds from PLAN §2.2.
const (
	WideMin = 100
	MidMin  = 70
)

// DefaultWidth is assumed when the width cannot be detected, e.g. when output
// is piped. Wide is the right default there: a pipe has no width limit.
const DefaultWidth = 100

// PickLayout maps a terminal width onto a layout.
func PickLayout(width int) Layout {
	switch {
	case width >= WideMin:
		return LayoutWide
	case width >= MidMin:
		return LayoutMid
	default:
		return LayoutMin
	}
}

// TerminalWidth reports the usable width of f. COLUMNS wins when set, which is
// also how tests pin the layout.
func TerminalWidth(f *os.File) int {
	if v := os.Getenv("COLUMNS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	if n := termWidth(f); n > 0 {
		return n
	}
	return DefaultWidth
}
