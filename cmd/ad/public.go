package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"

	"github.com/gomarkdown/markdown"
	htmlMd "github.com/gomarkdown/markdown/html"
	"github.com/gorilla/websocket"
	"github.com/tinyrange/ad/pkg/htm"
	"github.com/tinyrange/ad/pkg/htm/bootstrap"
	"github.com/tinyrange/ad/pkg/htm/html"
	"github.com/tinyrange/ad/pkg/htm/htmx"
	"github.com/tinyrange/ad/pkg/htm/xtermjs"
)

func (game *AttackDefenseGame) renderScoreboard() htm.Fragment {
	game.scoreboardMtx.RLock()
	defer game.scoreboardMtx.RUnlock()

	scoreboard := game.OverallState

	if scoreboard == nil {
		return nil
	}

	var headerRow htm.Group
	headerRow = append(headerRow, html.Text("#"))
	headerRow = append(headerRow, html.Text("Name"))
	headerRow = append(headerRow, html.Text("Points"))
	for _, service := range game.Config.Vulnbox.Services {
		headerRow = append(headerRow, html.Textf("%s Points", service.Name))
		headerRow = append(headerRow, html.Textf("%s Tick Points", service.Name))
		headerRow = append(headerRow, html.Textf("%s Attack Points", service.Name))
		headerRow = append(headerRow, html.Textf("%s Defense Points", service.Name))
		headerRow = append(headerRow, html.Textf("%s Uptime Points", service.Name))
	}

	var rows []htm.Group
	for _, team := range scoreboard.Teams {
		row := htm.Group{
			html.Textf("%d", team.Position),
			html.Textf("%s", team.Name),
			html.Textf("%f", team.Points),
		}

		for _, service := range game.Config.Vulnbox.Services {
			serviceState := team.Services[service.Id]
			if serviceState == nil {
				row = append(row, html.Text(""), html.Text(""), html.Text(""), html.Text(""), html.Text(""))
			} else {
				row = append(row,
					html.Textf("%f", serviceState.Points),
					html.Textf("%f", serviceState.TickPoints),
					html.Textf("%f", serviceState.AttackPoints),
					html.Textf("%f", serviceState.DefensePoints),
					html.Textf("%f", serviceState.UptimePoints),
				)
			}
		}

		rows = append(rows, row)
	}

	return bootstrap.Table(
		headerRow,
		rows,
	)
}

func (game *AttackDefenseGame) renderPage(ctx context.Context, path string) (htm.Fragment, error) {
	page, ok := game.Config.Pages[path]
	if !ok {
		return nil, nil
	}

	pagePath := game.ResolvePath(page.Path)

	pageContent, err := os.ReadFile(pagePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read page: %w", err)
	}

	doc := markdown.Parse(pageContent, nil)

	renderer := htmlMd.NewRenderer(htmlMd.RendererOptions{})

	body := markdown.Render(doc, renderer)

	return htm.UnsafeRawHTML(body), nil
}

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
				bootstrap.NavbarLink("/scoreboard", html.Text("Scoreboard")),
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
		body, err := game.renderPage(r.Context(), "/")
		if err != nil {
			slog.Error("failed to render page", "err", err)
			if err := htm.Render(r.Context(), w, game.publicPageError(err)); err != nil {
				slog.Error("failed to render page", "err", err)
			}
			return
		}

		page := game.publicPageLayout("Home", body)

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

	// GET /scoreboard lists the scoreboard for the overall state.
	handler.HandleFunc("GET /scoreboard", func(w http.ResponseWriter, r *http.Request) {
		page := game.renderScoreboard()
		if page == nil {
			page = game.publicPageError(fmt.Errorf("game has not started"))
		}

		if err := htm.Render(r.Context(), w, game.publicPageLayout("Scoreboard", page)); err != nil {
			slog.Error("failed to render page", "err", err)
		}
	})

	// GET /api/scoreboard returns the scoreboard for the overall state.
	handler.HandleFunc("GET /api/scoreboard", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		game.scoreboardMtx.RLock()
		defer game.scoreboardMtx.RUnlock()

		if err := json.NewEncoder(w).Encode(game.OverallState); err != nil {
			slog.Error("failed to encode scoreboard", "err", err)
		}
	})

	// GET /api/scoreboard/{tick} returns the scoreboard for a specific tick.
	handler.HandleFunc("GET /api/scoreboard/{tick}", func(w http.ResponseWriter, r *http.Request) {
		tickStr := r.PathValue("tick")

		tick, err := strconv.Atoi(tickStr)
		if err != nil {
			http.Error(w, "invalid tick", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		game.scoreboardMtx.RLock()
		defer game.scoreboardMtx.RUnlock()

		if tick > len(game.Ticks) {
			http.Error(w, "tick not found", http.StatusNotFound)
			return
		}

		if err := json.NewEncoder(w).Encode(game.Ticks[tick-1]); err != nil {
			slog.Error("failed to encode scoreboard", "err", err)
		}
	})

	for path, pageInfo := range game.Config.Pages {
		if path == "/" {
			continue
		}

		handler.HandleFunc("GET "+path, func(w http.ResponseWriter, r *http.Request) {
			body, err := game.renderPage(r.Context(), path)
			if err != nil {
				slog.Error("failed to render page", "err", err)
				if err := htm.Render(r.Context(), w, game.publicPageError(err)); err != nil {
					slog.Error("failed to render page", "err", err)
				}
				return
			}

			page := game.publicPageLayout(pageInfo.Title, body)

			if err := htm.Render(r.Context(), w, page); err != nil {
				slog.Error("failed to render page", "err", err)
			}
		})
	}

	// Router is allowed to be public since it uses an API key to lookup a configuration.
	game.Router.registerMux(handler)

	publicAddr := fmt.Sprintf("%s:%d", game.PublicIP, game.PublicPort)

	game.publicServer = &http.Server{
		Addr:    publicAddr,
		Handler: handler,
	}

	listener, err := net.Listen("tcp", publicAddr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	slog.Info("public server listening", "url", " "+game.FrontendUrl())

	go func() {
		if err := game.publicServer.Serve(listener); err != nil {
			slog.Error("failed to start server", "err", err)
		}
	}()

	return nil
}
