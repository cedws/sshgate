package cmd

import (
	"context"
	"log/slog"
	"os"

	"github.com/alecthomas/kong"
	"github.com/cedws/sshgate/pkg/sshgate"
)

type cli struct {
	ListenAddr string `help:"Address to listen on" default:":2222"`
	LogFormat  string `help:"Log format"`
	Config     string `help:"Path to JSON config file"`

	Serve      serveCmd      `cmd:"" default:"1" help:"Start the server"`
	JSONSchema jsonschemaCmd `cmd:"" name:"jsonschema" help:"Print config JSON schema"`
}

type serveCmd struct{}

func (s *serveCmd) Run(c *cli) error {
	var handler slog.Handler

	switch c.LogFormat {
	case "json":
		handler = slog.NewJSONHandler(os.Stderr, nil)
	case "text":
		fallthrough
	default:
		handler = slog.NewTextHandler(os.Stderr, nil)
	}

	slog.SetDefault(slog.New(handler))

	config, err := sshgate.ReadConfig(c.Config)
	if err != nil {
		return err
	}

	server := sshgate.New(config, c.ListenAddr)
	return server.ListenAndServe(context.Background())
}

func Execute() {
	var cli cli

	ctx := kong.Parse(
		&cli,
		kong.Name("sshgate"),
		kong.Description("SSH gateway with firewalling"),
		kong.UsageOnError(),
		kong.ConfigureHelp(kong.HelpOptions{
			Compact: true,
		}),
	)

	ctx.FatalIfErrorf(ctx.Run())
}
