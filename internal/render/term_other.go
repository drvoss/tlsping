//go:build !windows && !unix

package render

import "os"

// Platforms without a console API fall back to COLUMNS and the default width.
func termWidth(*os.File) int { return 0 }

func isTerminal(*os.File) bool { return false }

func enableVT(*os.File) bool { return false }
