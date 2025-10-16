package cmd

import (
	"context"
	"errors"
	"log/slog"
	"os"

	"github.com/alecthomas/kong"
	"github.com/cedws/sshgate/pkg/sshgate"
)

type cli struct {
	ListenAddr     string `help:"Address to listen on" default:":2222"`
	Ruleless       bool   `help:"Run in ruleless mode"`
	NoConfigReload bool   `help:"Disable config reload"`
	LogFormat      string `help:"Log format"`
	Config         string `help:"Path to JSON config file"`

	Serve      serveCmd      `cmd:"" default:"1" help:"Start the server"`
	JSONSchema jsonschemaCmd `cmd:"" name:"jsonschema" help:"Print config JSON schema"`
}

type serveCmd struct{}

func (s *serveCmd) Run(cli *cli) error {
	var handler slog.Handler

	switch cli.LogFormat {
	case "json":
		handler = slog.NewJSONHandler(os.Stderr, nil)
	case "text":
		fallthrough
	default:
		handler = slog.NewTextHandler(os.Stderr, nil)
	}

	slog.SetDefault(slog.New(handler))

	for {
		config, err := sshgate.ReadConfig(cli.Config)
		if err != nil {
			return err
		}

		if err := serve(context.Background(), cli, config); err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
	}
}

func serve(ctx context.Context, c *cli, config *sshgate.Config) error {
	var opts []sshgate.Option

	if c.Ruleless {
		opts = append(opts, sshgate.WithRulelessMode())
	}
	if !c.NoConfigReload {
		opts = append(opts, sshgate.WithConfigReload())
	}

	server, err := sshgate.New(config, c.ListenAddr, opts...)
	if err != nil {
		return err
	}

	return server.ListenAndServe(ctx)
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
