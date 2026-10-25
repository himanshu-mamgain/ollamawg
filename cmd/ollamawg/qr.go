package main

import (
	"strings"

	"github.com/himanshu-mamgain/ollamawg"
)

type qrStyle int

const (
	qrBlocks qrStyle = iota // Unicode half blocks: compact, needs a font that has them
	qrANSI                  // coloured spaces: works with any font, but twice as tall
)

// terminalQR renders a QR code that this terminal can display, and makes
// the window tall enough to show it whole (on Windows). extra is the number
// of lines printed before it that should stay visible too.
func terminalQR(text string, extra int) (string, error) {
	render := ollamawg.QRTerminal
	if prepareConsole() == qrANSI {
		render = ollamawg.QRTerminalANSI
	}
	code, err := render(text)
	if err != nil {
		return "", err
	}
	fitConsole(strings.Count(code, "\n") + extra + 1) // +1 for the prompt after it
	return code, nil
}
