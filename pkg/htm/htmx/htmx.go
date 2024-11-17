package htmx

import (
	_ "embed"
	"fmt"
	"strings"
	"time"

	"github.com/tinyrange/ad/pkg/htm"
	"github.com/tinyrange/ad/pkg/htm/html"
)

//go:embed htmx.min.js
var JavascriptSrcRaw string

var JavaScriptSrc = html.JavaScript(JavascriptSrcRaw)

func Get(target string) htm.Fragment {
	return htm.Attr("hx-get", target)
}

func Post(target string) htm.Fragment {
	return htm.Attr("hx-post", target)
}

type Event string

const (
	EventKeyup Event = "keyup"
)

type Modifier string

const (
	ModifierOnce    Modifier = "once"
	ModifierChanged Modifier = "changed"
)

func ModifierDelay(delay time.Duration) Modifier {
	return Modifier(fmt.Sprintf("delay:%dms", delay.Milliseconds()))
}

func Trigger(event Event, modifiers ...Modifier) htm.Fragment {
	var args []string
	args = append(args, string(event))
	for _, m := range modifiers {
		args = append(args, string(m))
	}
	return htm.Attr("hx-trigger", strings.Join(args, " "))
}

func Target(target html.Id) htm.Fragment {
	return htm.Attr("hx-target", "#"+string(target))
}

func Include(target ...string) htm.Fragment {
	return htm.Attr("hx-include", strings.Join(target, ","))
}

func FormName(name string) string {
	return fmt.Sprintf("[name='%s']", name)
}
