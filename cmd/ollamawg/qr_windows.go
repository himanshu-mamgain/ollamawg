package main

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// consoleFontInfoEx is CONSOLE_FONT_INFOEX.
type consoleFontInfoEx struct {
	size   uint32
	font   uint32
	x, y   int16
	family uint32
	weight uint32
	face   [32]uint16
}

const tmpfTrueType = 0x04 // TMPF_TRUETYPE in FontFamily

var (
	kernel32      = windows.NewLazySystemDLL("kernel32.dll")
	procGetFontEx = kernel32.NewProc("GetCurrentConsoleFontEx")
	procSetFontEx = kernel32.NewProc("SetCurrentConsoleFontEx")
	procSetWindow = kernel32.NewProc("SetConsoleWindowInfo")
)

// fitConsole makes the console window at least lines rows tall, as far as
// the screen allows, so a QR code can be seen (and scanned) in one piece.
// The default cmd.exe window has 30 rows; a WireGuard config's QR needs ~33.
func fitConsole(lines int) {
	h := windows.Handle(os.Stdout.Fd())
	var info windows.ConsoleScreenBufferInfo
	if windows.GetConsoleScreenBufferInfo(h, &info) != nil {
		return
	}
	w := info.Window
	if int(w.Bottom-w.Top+1) >= lines {
		return
	}
	rows := int16(lines)
	if rows > info.MaximumWindowSize.Y {
		rows = info.MaximumWindowSize.Y
	}
	if w.Top+rows > info.Size.Y {
		w.Top = info.Size.Y - rows
	}
	w.Bottom = w.Top + rows - 1
	procSetWindow.Call(uintptr(h), 1, uintptr(unsafe.Pointer(&w)))
	keepOnScreen()
}

var (
	user32             = windows.NewLazySystemDLL("user32.dll")
	procConsoleWindow  = kernel32.NewProc("GetConsoleWindow")
	procGetWindowRect  = user32.NewProc("GetWindowRect")
	procMonitorFromWnd = user32.NewProc("MonitorFromWindow")
	procGetMonitorInfo = user32.NewProc("GetMonitorInfoW")
	procSetWindowPos   = user32.NewProc("SetWindowPos")
)

type rect struct{ left, top, right, bottom int32 }

// keepOnScreen moves the console window up if growing it pushed its bottom
// edge below the screen's work area.
func keepOnScreen() {
	hwnd, _, _ := procConsoleWindow.Call()
	if hwnd == 0 {
		return // e.g. Windows Terminal, which manages its own window
	}
	var r rect
	if ok, _, _ := procGetWindowRect.Call(hwnd, uintptr(unsafe.Pointer(&r))); ok == 0 {
		return
	}
	mon, _, _ := procMonitorFromWnd.Call(hwnd, 2) // MONITOR_DEFAULTTONEAREST
	mi := struct {
		size          uint32
		monitor, work rect
		flags         uint32
	}{size: 40}
	if ok, _, _ := procGetMonitorInfo.Call(mon, uintptr(unsafe.Pointer(&mi))); ok == 0 || r.bottom <= mi.work.bottom {
		return
	}
	top := mi.work.bottom - (r.bottom - r.top)
	if top < mi.work.top {
		top = mi.work.top
	}
	const swpNoSize, swpNoZOrder = 0x0001, 0x0004
	procSetWindowPos.Call(hwnd, 0, uintptr(r.left), uintptr(top), 0, 0, swpNoSize|swpNoZOrder)
}

// prepareConsole gets the console ready to draw a QR code. The block
// characters need a TrueType font, but cmd.exe still defaults to a raster
// font (e.g. "8514oem") that draws them as blanks. In that case it switches
// this console window, not the saved settings, to Consolas.
func prepareConsole() qrStyle {
	h := uintptr(os.Stdout.Fd())
	fi := consoleFontInfoEx{size: uint32(unsafe.Sizeof(consoleFontInfoEx{}))}
	if r, _, _ := procGetFontEx.Call(h, 0, uintptr(unsafe.Pointer(&fi))); r == 0 {
		return qrBlocks // not a console (redirected), or an unknown host: plain text is best
	}
	if fi.family&tmpfTrueType != 0 {
		return qrBlocks
	}
	want := consoleFontInfoEx{size: fi.size, y: 14, family: 0x36, weight: 400} // FF_MODERN|TMPF_TRUETYPE|FIXED_PITCH
	copy(want.face[:], windows.StringToUTF16("Consolas"))
	if r, _, _ := procSetFontEx.Call(h, 0, uintptr(unsafe.Pointer(&want))); r != 0 {
		got := consoleFontInfoEx{size: fi.size}
		if r, _, _ := procGetFontEx.Call(h, 0, uintptr(unsafe.Pointer(&got))); r != 0 && got.family&tmpfTrueType != 0 {
			return qrBlocks
		}
	}
	if enableANSI(windows.Handle(h)) {
		return qrANSI
	}
	return qrBlocks
}

// enableANSI turns on ANSI escape processing (Windows 10 and later) and
// reports whether it is on.
func enableANSI(h windows.Handle) bool {
	var mode uint32
	if windows.GetConsoleMode(h, &mode) != nil {
		return false
	}
	if mode&windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0 {
		return true
	}
	return windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING) == nil
}
