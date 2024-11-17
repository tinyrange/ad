package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/tinyrange/ad/pkg/htm"
	"github.com/tinyrange/ad/pkg/htm/bootstrap"
	"github.com/tinyrange/ad/pkg/htm/html"
	"github.com/tinyrange/ad/pkg/htm/htmx"
)

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
		var teamList []htm.Group
		for _, team := range game.Teams {
			teamList = append(teamList, htm.Group{
				htm.Text(team.DisplayName),
				htm.Text(team.IP()),
			})
		}

		page := game.privatePageLayout("Home",
			bootstrap.Card(
				bootstrap.CardTitle("Teams"),
				bootstrap.Table(
					htm.Group{
						htm.Text("Name"),
						htm.Text("IP"),
					},
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
					bootstrap.FormField("flag", "Flag", html.FormOptions{
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

	// Add an API endpoint for getting a list of team IPs.
	game.privateServer.HandleFunc("GET /api/teams", func(w http.ResponseWriter, r *http.Request) {
		playerTeam := GetInfo(r.Context())
		if playerTeam == nil {
			http.Error(w, "team not found", http.StatusNotFound)
			return
		}

		teams := make([]struct {
			Self        bool   `json:"self"`
			IP          string `json:"ip"`
			DisplayName string `json:"display_name"`
		}, len(game.Teams))

		for i, team := range game.Teams {
			teams[i] = struct {
				Self        bool   `json:"self"`
				IP          string `json:"ip"`
				DisplayName string `json:"display_name"`
			}{
				Self:        team.ID == playerTeam.ID,
				IP:          team.IP(),
				DisplayName: team.DisplayName,
			}
		}

		json.NewEncoder(w).Encode(teams)
	})

	return nil
}
