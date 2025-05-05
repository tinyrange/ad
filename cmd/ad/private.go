package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/tinyrange/ad/pkg/htm"
	"github.com/tinyrange/ad/pkg/htm/bootstrap"
	"github.com/tinyrange/ad/pkg/htm/html"
	"github.com/tinyrange/ad/pkg/htm/htmx"
	"golang.org/x/crypto/ssh"
)

var (
	CONTEXT_KEY_TEAM = CONTEXT_KEY("team")
)

func GetInfo(ctx context.Context) *TargetInfo {
	t, ok := ctx.Value(CONTEXT_KEY_TEAM).(TargetInfo)
	if !ok {
		return nil
	}

	return &t
}

type serviceApiResponse struct {
	Id   int    `json:"id"`
	Name string `json:"name"`
	Port int    `json:"port"`
}

type teamApiResponse struct {
	Self        bool                 `json:"self"`
	Id          int                  `json:"id"`
	IP          string               `json:"ip"`
	DisplayName string               `json:"display_name"`
	Services    []serviceApiResponse `json:"services"`
}

func (game *AttackDefenseGame) privatePageError(err error) htm.Fragment {
	return game.privatePageLayout("Error", bootstrap.Alert(bootstrap.AlertColorDanger, htm.Text(err.Error())))
}

func (game *AttackDefenseGame) privatePageLayout(title string, body ...htm.Fragment) htm.Fragment {
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
				bootstrap.NavbarLink("/vulnbox", html.Text("Vulnbox")),
			),
			html.Div(bootstrap.Container, htm.Group(body)),
		),
	)
}

func (game *AttackDefenseGame) registerPrivateServer() error {
	game.privateServer = http.NewServeMux()

	// Add a simple homepage for the private server.
	game.privateServer.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Add a card on the page with a table of team.
		var headerRow htm.Group
		headerRow = append(headerRow, htm.Text("Name"))
		headerRow = append(headerRow, htm.Text("IP"))

		for _, service := range game.Config.Vulnbox.Services {
			headerRow = append(headerRow, htm.Text(service.Name()))
		}

		var teamList []htm.Group
		for _, team := range game.Teams {
			row := htm.Group{
				htm.Text(team.DisplayName),
				htm.Text(team.IP()),
			}

			for _, service := range game.Config.Vulnbox.Services {
				serviceUrl := fmt.Sprintf("http://%s:%d", team.IP(), service.Port())
				row = append(row, html.Link(serviceUrl, html.Textf("%s", serviceUrl)))
			}

			teamList = append(teamList, row)

			// TODO(joshua): Only add the bot if this is our own team.
			if game.Config.Vulnbox.Bot.Enabled {
				row := htm.Group{
					htm.Text(team.DisplayName + " Bot"),
					htm.Text(team.BotIP()),
				}

				for _, service := range game.Config.Vulnbox.Services {
					serviceUrl := fmt.Sprintf("http://%s:%d", team.BotIP(), service.Port())
					row = append(row, html.Link(serviceUrl, html.Textf("%s", serviceUrl)))
				}

				teamList = append(teamList, row)
			}
		}

		page := game.privatePageLayout("Home",
			bootstrap.Card(
				bootstrap.CardTitle("Teams"),
				bootstrap.Table(
					headerRow,
					teamList,
				),
			),
			// Add a card on the page with a flag submission form.
			bootstrap.Card(
				bootstrap.CardTitle("Submit Flag"),
				html.Form(
					html.Id("flag-form"),
					htmx.Post("/api/flag"),
					htmx.Target("flag-result"),
					bootstrap.FormField("Flag", "flag", html.FormOptions{
						Kind:     html.FormFieldText,
						Required: true,
						Value:    "",
					}),
					bootstrap.SubmitButton("Submit", bootstrap.ButtonColorPrimary),
				),
				html.Div(html.Id("flag-result")),
			),
		)

		if err := htm.Render(r.Context(), w, page); err != nil {
			slog.Error("failed to render page", "err", err)
		}
	})

	// Add a API endpoint for submitting flags.
	game.privateServer.HandleFunc("POST /api/flag", func(w http.ResponseWriter, r *http.Request) {
		info := GetInfo(r.Context())
		if info == nil {
			http.Error(w, "team not found", http.StatusNotFound)
			return
		}

		flag := r.FormValue("flag")
		if flag == "" {
			http.Error(w, "flag not found", http.StatusBadRequest)

			return
		}

		status := game.submitFlag(*info, flag)

		if status != FlagAccepted {
			slog.Info("received invalid flag", "team", info.Name, "flag", flag, "status", status)
		}

		fmt.Fprintf(w, "%s\n", status)
	})

	// GET /vulnbox renders the vulnbox connection info.
	game.privateServer.HandleFunc("GET /vulnbox", func(w http.ResponseWriter, r *http.Request) {
		var teamList htm.Group

		for _, team := range game.Teams {
			secureConfig, err := team.GetSSHConfig()
			if err != nil {
				slog.Error("failed to get secure config", "err", err)
				continue
			}

			publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(secureConfig.PublicKey))
			if err != nil {
				slog.Error("failed to parse public key", "err", err)
				continue
			}

			teamList = append(teamList,
				bootstrap.Card(
					bootstrap.CardTitle(team.DisplayName),
					html.P(html.Strong(htm.Text("SSH Command: ")), html.Code(html.Textf("ssh -p 2222 root@%s", team.IP()))),
					bootstrap.Table(
						nil,
						[]htm.Group{
							{htm.Text("IP"), html.Code(html.Textf("%s", team.IP()))},
							{htm.Text("Port"), html.Code(html.Textf("%d", 2222))},
							{htm.Text("Username"), html.Code(html.Textf("%s", "root"))},
							{htm.Text("Password"), html.Code(html.Textf("%s", secureConfig.Password))},
							{htm.Text("Fingerprint"), html.Code(html.Textf("%s", ssh.FingerprintSHA256(publicKey)))},
						},
					),
				),
			)
		}

		if err := htm.Render(r.Context(), w, game.privatePageLayout("Vulnbox", teamList)); err != nil {
			slog.Error("failed to render page", "err", err)
		}
	})

	// Add an API endpoint for getting a list of team IPs.
	game.privateServer.HandleFunc("GET /api/teams", func(w http.ResponseWriter, r *http.Request) {
		playerTeam := GetInfo(r.Context())
		if playerTeam == nil {
			http.Error(w, "team not found", http.StatusNotFound)
			return
		}

		teams := make([]teamApiResponse, len(game.Teams))

		for i, team := range game.Teams {
			teams[i] = teamApiResponse{
				Self:        team.ID == playerTeam.ID,
				Id:          team.ID,
				IP:          team.IP(),
				DisplayName: team.DisplayName,
			}

			for _, service := range game.Config.Vulnbox.Services {
				teams[i].Services = append(teams[i].Services, serviceApiResponse{
					Id:   service.Id,
					Name: service.Name(),
					Port: service.Port(),
				})
			}
		}

		json.NewEncoder(w).Encode(teams)
	})

	// GET /scoreboard lists the scoreboard for the overall state.
	game.privateServer.HandleFunc("GET /scoreboard", func(w http.ResponseWriter, r *http.Request) {
		page := game.renderScoreboard()
		if page == nil {
			page = game.privatePageError(fmt.Errorf("game has not started"))
		} else {
			page = game.privatePageLayout("Scoreboard", page)
		}

		if err := htm.Render(r.Context(), w, page); err != nil {
			slog.Error("failed to render page", "err", err)
		}
	})

	// GET /api/scoreboard returns the scoreboard for the overall state.
	game.privateServer.HandleFunc("GET /api/scoreboard", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		game.scoreboardMtx.RLock()
		defer game.scoreboardMtx.RUnlock()

		if err := json.NewEncoder(w).Encode(game.OverallState); err != nil {
			slog.Error("failed to encode scoreboard", "err", err)
		}
	})

	// GET /api/scoreboard/{tick} returns the scoreboard for a specific tick.
	game.privateServer.HandleFunc("GET /api/scoreboard/{tick}", func(w http.ResponseWriter, r *http.Request) {
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

	return nil
}
