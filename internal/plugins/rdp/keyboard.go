// Copyright 2026 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package rdp

// keyMapping maps an ASCII character to its PS/2 Set 1 scancode
// and whether the Shift key must be held.
type keyMapping struct {
	scancode uint16
	shift    bool
}

// leftShiftScancodeSC is the PS/2 Set 1 scancode for Left Shift.
const leftShiftScancodeSC = 0x2A

// enterScancode is the PS/2 Set 1 scancode for Enter.
const enterScancode = 0x1C

// leftWinScancode is the PS/2 Set 1 scancode for the Left Windows key (extended).
const leftWinScancode = 0xE05B

// uKeyScancode is the PS/2 Set 1 scancode for the U key.
const uKeyScancode = 0x16

// asciiToScancode maps printable ASCII characters to PS/2 Set 1 scancodes.
// Shift is required for uppercase letters and symbols on shifted keys.
var asciiToScancode = map[byte]keyMapping{
	// Letters (lowercase)
	'a': {0x1E, false}, 'b': {0x30, false}, 'c': {0x2E, false}, 'd': {0x20, false},
	'e': {0x12, false}, 'f': {0x21, false}, 'g': {0x22, false}, 'h': {0x23, false},
	'i': {0x17, false}, 'j': {0x24, false}, 'k': {0x25, false}, 'l': {0x26, false},
	'm': {0x32, false}, 'n': {0x31, false}, 'o': {0x18, false}, 'p': {0x19, false},
	'q': {0x10, false}, 'r': {0x13, false}, 's': {0x1F, false}, 't': {0x14, false},
	'u': {0x16, false}, 'v': {0x2F, false}, 'w': {0x11, false}, 'x': {0x2D, false},
	'y': {0x15, false}, 'z': {0x2C, false},
	// Letters (uppercase — same scancode, shift=true)
	'A': {0x1E, true}, 'B': {0x30, true}, 'C': {0x2E, true}, 'D': {0x20, true},
	'E': {0x12, true}, 'F': {0x21, true}, 'G': {0x22, true}, 'H': {0x23, true},
	'I': {0x17, true}, 'J': {0x24, true}, 'K': {0x25, true}, 'L': {0x26, true},
	'M': {0x32, true}, 'N': {0x31, true}, 'O': {0x18, true}, 'P': {0x19, true},
	'Q': {0x10, true}, 'R': {0x13, true}, 'S': {0x1F, true}, 'T': {0x14, true},
	'U': {0x16, true}, 'V': {0x2F, true}, 'W': {0x11, true}, 'X': {0x2D, true},
	'Y': {0x15, true}, 'Z': {0x2C, true},
	// Numbers
	'1': {0x02, false}, '2': {0x03, false}, '3': {0x04, false}, '4': {0x05, false},
	'5': {0x06, false}, '6': {0x07, false}, '7': {0x08, false}, '8': {0x09, false},
	'9': {0x0A, false}, '0': {0x0B, false},
	// Shifted number row
	'!': {0x02, true}, '@': {0x03, true}, '#': {0x04, true}, '$': {0x05, true},
	'%': {0x06, true}, '^': {0x07, true}, '&': {0x08, true}, '*': {0x09, true},
	'(': {0x0A, true}, ')': {0x0B, true},
	// Punctuation (unshifted)
	'-': {0x0C, false}, '=': {0x0D, false}, '[': {0x1A, false}, ']': {0x1B, false},
	'\\': {0x2B, false}, ';': {0x27, false}, '\'': {0x28, false}, '`': {0x29, false},
	',': {0x33, false}, '.': {0x34, false}, '/': {0x35, false},
	// Punctuation (shifted)
	'_': {0x0C, true}, '+': {0x0D, true}, '{': {0x1A, true}, '}': {0x1B, true},
	'|': {0x2B, true}, ':': {0x27, true}, '"': {0x28, true}, '~': {0x29, true},
	'<': {0x33, true}, '>': {0x34, true}, '?': {0x35, true},
	// Whitespace
	' ':  {0x39, false},
	'\t': {0x0F, false},
}

// jsCodeToScancode maps JavaScript KeyboardEvent.code values to PS/2 Set 1 scancodes.
// Used by the web terminal to translate browser key events to RDP scancodes.
var jsCodeToScancode = map[string]uint16{
	// Letters
	"KeyA": 0x1E, "KeyB": 0x30, "KeyC": 0x2E, "KeyD": 0x20,
	"KeyE": 0x12, "KeyF": 0x21, "KeyG": 0x22, "KeyH": 0x23,
	"KeyI": 0x17, "KeyJ": 0x24, "KeyK": 0x25, "KeyL": 0x26,
	"KeyM": 0x32, "KeyN": 0x31, "KeyO": 0x18, "KeyP": 0x19,
	"KeyQ": 0x10, "KeyR": 0x13, "KeyS": 0x1F, "KeyT": 0x14,
	"KeyU": 0x16, "KeyV": 0x2F, "KeyW": 0x11, "KeyX": 0x2D,
	"KeyY": 0x15, "KeyZ": 0x2C,
	// Numbers
	"Digit1": 0x02, "Digit2": 0x03, "Digit3": 0x04, "Digit4": 0x05,
	"Digit5": 0x06, "Digit6": 0x07, "Digit7": 0x08, "Digit8": 0x09,
	"Digit9": 0x0A, "Digit0": 0x0B,
	// Function keys
	"F1": 0x3B, "F2": 0x3C, "F3": 0x3D, "F4": 0x3E,
	"F5": 0x3F, "F6": 0x40, "F7": 0x41, "F8": 0x42,
	"F9": 0x43, "F10": 0x44, "F11": 0x57, "F12": 0x58,
	// Modifiers
	"ShiftLeft": 0x2A, "ShiftRight": 0x36,
	"ControlLeft": 0x1D, "ControlRight": 0xE01D,
	"AltLeft": 0x38, "AltRight": 0xE038,
	// Special keys
	"Escape": 0x01, "Backspace": 0x0E, "Tab": 0x0F,
	"Enter": 0x1C, "Space": 0x39, "CapsLock": 0x3A,
	// Punctuation
	"Minus": 0x0C, "Equal": 0x0D,
	"BracketLeft": 0x1A, "BracketRight": 0x1B,
	"Backslash": 0x2B, "Semicolon": 0x27, "Quote": 0x28,
	"Backquote": 0x29, "Comma": 0x33, "Period": 0x34, "Slash": 0x35,
	// Navigation
	"ArrowUp": 0xE048, "ArrowDown": 0xE050,
	"ArrowLeft": 0xE04B, "ArrowRight": 0xE04D,
	"Home": 0xE047, "End": 0xE04F,
	"PageUp": 0xE049, "PageDown": 0xE051,
	"Insert": 0xE052, "Delete": 0xE053,
	// Windows keys
	"MetaLeft": 0xE05B, "MetaRight": 0xE05C,
}
