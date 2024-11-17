package xtermjs

import (
	"github.com/tinyrange/ad/pkg/htm/html"

	_ "embed"
)

//go:embed ssh_static/ssh_terminal.js
var sshJsRaw string

var SSH_JS = html.JavaScript(sshJsRaw)

var SSH_CSS = html.Style(`
#terminal {
	min-height: 300px;
	max-height: 50vh;
}
div.fillScreen {
	position: fixed;
	top: 0;
	left: 0;
	max-height: 100vh !important;
	z-index: 100;
}

button.fillScreen {
	position: fixed;
	bottom: 20px;
	right: 20px;
	z-index: 101;
}`)

//go:embed ssh_static/xterm.min.js
var xtermJsRaw string

//go:embed ssh_static/xterm-addon-fit.min.js
var xtermAddonFitRaw string

//go:embed ssh_static/xterm.css
var xtermCssRaw string

var XTERM_JS = html.JavaScript(xtermJsRaw)

var XTERM_ADDON_FIT = html.JavaScript(xtermAddonFitRaw)

var XTERM_CSS = html.Style(xtermCssRaw)
