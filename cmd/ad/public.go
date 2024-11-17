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

func (game *AttackDefenseGame) publicPageError(err error) htm.Fragment {
	return game.publicPageLayout("Error", bootstrap.Alert(bootstrap.AlertColorDanger, htm.Text(err.Error())))
}

func (game *AttackDefenseGame) publicPageLayout(title string, body ...htm.Fragment) htm.Fragment {
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
				bootstrap.NavbarBrand("/", html.Text(game.Config.Title)),
				bootstrap.NavbarLink("/instances", html.Text("Instances")),
				bootstrap.NavbarLink("/events", html.Text("Events")),
				bootstrap.NavbarLink("/devices", html.Text("Devices")),
			),
			html.Div(bootstrap.Container, htm.Group(body)),
		),
	)
}

func (game *AttackDefenseGame) startPublicServer() error {
	handler := http.NewServeMux()

	handler.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		page := game.publicPageLayout("Home")

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

		page := game.publicPageLayout("Instances", instanceList...)

		if err := htm.Render(r.Context(), w, page); err != nil {
			slog.Error("failed to render page", "err", err)
		}
	})

	// GET /connect/{instance} provides a WebSSH terminal to the instance.
	handler.HandleFunc("GET /connect/{instance}", func(w http.ResponseWriter, r *http.Request) {
		instanceId := r.PathValue("instance")

		if _, err := game.getInstance(instanceId); err != nil {
			if err := htm.Render(r.Context(), w, game.publicPageError(err)); err != nil {
				slog.Error("failed to render page", "err", err)
			}
			return
		}

		page := game.publicPageLayout("Connect",
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

	handler.HandleFunc("GET /events", func(w http.ResponseWriter, r *http.Request) {
		events := game.GetEvents()

		var eventList []htm.Fragment

		for _, event := range events {
			eventList = append(eventList, html.Div(
				bootstrap.Card(
					bootstrap.CardTitle(event),
					html.Form(
						html.FormTarget("POST", "/api/event"),
						html.HiddenFormField(html.NewId(), "name", event),
						bootstrap.SubmitButton(event, bootstrap.ButtonColorPrimary),
					),
				),
			))
		}

		page := game.publicPageLayout("Events", eventList...)

		if err := htm.Render(r.Context(), w, page); err != nil {
			slog.Error("failed to render page", "err", err)
		}
	})

	// POST /event runs an event by name.
	handler.HandleFunc("POST /api/event", func(w http.ResponseWriter, r *http.Request) {
		name := r.FormValue("name")

		if err := game.RunEvent(name); err != nil {
			slog.Error("failed to run event", "err", err)
			if err := htm.Render(r.Context(), w, game.publicPageError(err)); err != nil {
				slog.Error("failed to render page", "err", err)
			}
			return
		}

		http.Redirect(w, r, "/", http.StatusFound)
	})

	// GET /devices lists all devices and their WireGuard configuration and a button to add a new device.
	handler.HandleFunc("GET /devices", func(w http.ResponseWriter, r *http.Request) {
		devices := game.GetDevices()

		var deviceList []htm.Fragment

		for _, device := range devices {
			deviceList = append(deviceList, html.Div(
				bootstrap.Card(
					bootstrap.CardTitle(device.Name),
					html.Div(html.Strong(html.Text("IP Adddress:")), html.Textf("%s", device.IP)),
					bootstrap.LinkButton("/wireguard/"+device.ConfigKey, bootstrap.ButtonColorPrimary, html.Text("Download Config")),
				),
			))
		}

		page := game.publicPageLayout("Devices",
			htm.Group(deviceList),
			html.Form(
				html.FormTarget("POST", "/api/device"),
				bootstrap.FormField("Name", "name", html.FormOptions{Kind: html.FormFieldText, Required: true, Value: "", Placeholder: "Device Name"}),
				bootstrap.SubmitButton("Add Device", bootstrap.ButtonColorPrimary),
			),
		)

		if err := htm.Render(r.Context(), w, page); err != nil {
			slog.Error("failed to render page", "err", err)
		}
	})

	// POST /api/device adds a new device.
	handler.HandleFunc("POST /api/device", func(w http.ResponseWriter, r *http.Request) {
		name := r.FormValue("name")

		if name == "" {
			if err := htm.Render(r.Context(), w, game.publicPageError(fmt.Errorf("name is required"))); err != nil {
				slog.Error("failed to render page", "err", err)
			}
			return
		}

		if err := game.AddDevice(name); err != nil {
			slog.Error("failed to add device", "err", err)
			if err := htm.Render(r.Context(), w, game.publicPageError(err)); err != nil {
				slog.Error("failed to render page", "err", err)
			}
			return
		}

		http.Redirect(w, r, "/devices", http.StatusFound)
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

	slog.Info("public server listening", "url", fmt.Sprintf(" http://%s:%d", game.Config.Frontend.Address, game.Config.Frontend.Port))

	go func() {
		if err := game.publicServer.Serve(listener); err != nil {
			slog.Error("failed to start server", "err", err)
		}
	}()

	return nil
}
