package main

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"

	"github.com/gorilla/websocket"
	"github.com/tinyrange/ad/pkg/htm"
	"github.com/tinyrange/ad/pkg/htm/bootstrap"
	"github.com/tinyrange/ad/pkg/htm/html"
	"github.com/tinyrange/ad/pkg/htm/htmx"
	"github.com/tinyrange/ad/pkg/htm/xtermjs"
)

var upgrader = websocket.Upgrader{}

func (game *AttackDefenseGame) pageError(err error) htm.Fragment {
	return game.pageLayout("Error", bootstrap.Alert(bootstrap.AlertColorDanger, htm.Text(err.Error())))
}

func (game *AttackDefenseGame) pageLayout(title string, body ...htm.Fragment) htm.Fragment {
	return html.Html(
		htm.Attr("lang", "en"),
		html.Head(
			html.MetaCharset("UTF-8"),
			html.Title(fmt.Sprintf("%s - %s", game.Config.Title, title)),
			html.MetaViewport("width=device-width, initial-scale=1"),
			bootstrap.CSSSrc,
			bootstrap.JavaScriptSrc,
			bootstrap.ColorPickerSrc,
			htmx.JavaScriptSrc,
		),
		html.Body(
			bootstrap.Navbar(
				bootstrap.NavbarBrand("/", html.Textf("%s - %s", game.Config.Title, title)),
			),
			html.Div(bootstrap.Container, htm.Group(body)),
		),
	)
}

func (game *AttackDefenseGame) startFrontendServer() error {
	handler := http.NewServeMux()

	handler.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		page := game.pageLayout("Home")

		if err := htm.Render(r.Context(), w, page); err != nil {
			slog.Error("failed to render page", "err", err)
		}
	})

	// GET /instances lists all running TinyRange instances and provides a button to SSH via WebSSH.
	handler.HandleFunc("GET /instances", func(w http.ResponseWriter, r *http.Request) {
		instances := game.getInstances()

		var instanceList []htm.Fragment

		for _, instance := range instances {
			instanceList = append(instanceList, html.Div(
				bootstrap.Card(
					bootstrap.CardTitle(instance.Name()),
					bootstrap.LinkButton("/connect/"+instance.InstanceId(), bootstrap.ButtonColorPrimary, html.Text("Connect")),
				),
			))
		}

		page := game.pageLayout("Instances", instanceList...)

		if err := htm.Render(r.Context(), w, page); err != nil {
			slog.Error("failed to render page", "err", err)
		}
	})

	// GET /connect/{instance} provides a WebSSH terminal to the instance.
	handler.HandleFunc("GET /connect/{instance}", func(w http.ResponseWriter, r *http.Request) {
		instanceId := r.PathValue("instance")

		if _, err := game.getInstance(instanceId); err != nil {
			if err := htm.Render(r.Context(), w, game.pageError(err)); err != nil {
				slog.Error("failed to render page", "err", err)
			}
			return
		}

		page := game.pageLayout("Connect",
			htm.Group{
				xtermjs.XTERM_CSS,
				xtermjs.XTERM_JS,
				xtermjs.XTERM_ADDON_FIT,
				bootstrap.Button(bootstrap.ButtonColorDark, html.Text("Toggle Fill Screen"), html.Id("fillScreen")),
				html.Div(html.Id("terminal"), htm.Attr("data-connect", "/api/connect/"+instanceId)),
				xtermjs.SSH_CSS,
				xtermjs.SSH_JS,
			},
		)

		if err := htm.Render(r.Context(), w, page); err != nil {
			slog.Error("failed to render page", "err", err)
		}
	})

	// /api/connect/{instance} provides a WebSocket connection to the instance.
	handler.HandleFunc("/api/connect/{instance}", func(w http.ResponseWriter, r *http.Request) {
		instanceId := r.PathValue("instance")

		instance, err := game.getInstance(instanceId)
		if err != nil {
			slog.Error("failed to get instance", "err", err)
			http.Error(w, "instance not found", http.StatusNotFound)
			return
		}

		// Upgrade the connection to a WebSocket.
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			slog.Error("failed to upgrade connection", "err", err)
			return
		}

		if err := instance.WebSSHHandler(conn); err != nil {
			slog.Error("failed to handle WebSSH", "err", err)
		}
	})

	// POST /event runs an event by name.
	handler.HandleFunc("POST /event", func(w http.ResponseWriter, r *http.Request) {
		name := r.FormValue("name")

		if err := game.RunEvent(name); err != nil {
			slog.Error("failed to run event", "err", err)
			if err := htm.Render(r.Context(), w, game.pageError(err)); err != nil {
				slog.Error("failed to render page", "err", err)
			}
			return
		}

		http.Redirect(w, r, "/", http.StatusFound)
	})

	// Router is allowed to be public since it uses an API key to lookup a configuration.
	game.Router.registerMux(handler)

	game.publicServer = &http.Server{
		Addr:    game.Config.Frontend.Address,
		Handler: handler,
	}

	listener, err := net.Listen("tcp", game.Config.Frontend.Address+":"+fmt.Sprint(game.Config.Frontend.Port))
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	slog.Info("frontend server listening", "url", fmt.Sprintf(" http://%s:%d", game.Config.Frontend.Address, game.Config.Frontend.Port))

	go func() {
		if err := game.publicServer.Serve(listener); err != nil {
			slog.Error("failed to start server", "err", err)
		}
	}()

	return nil
}
