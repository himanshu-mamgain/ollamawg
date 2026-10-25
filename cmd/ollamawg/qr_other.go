//go:build !windows

package main

// prepareConsole: Unix terminals draw the block characters fine.
func prepareConsole() qrStyle { return qrBlocks }

// fitConsole: Unix terminals can't be resized from here; users scroll or zoom.
func fitConsole(int) {}
