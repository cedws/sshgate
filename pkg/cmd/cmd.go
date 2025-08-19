package cmd

import (
	"context"

	"github.com/alecthomas/kong"
	"github.com/cedws/sshgate/pkg/sshgate"
)

type cli struct {
	ListenAddr string `help:"Address to listen on" default:":2222"`
	Config     string `help:"Path to JSON config file"`
}

func (c *cli) Run() error {
	config, err := sshgate.Open(c.Config)
	if err != nil {
		return err
	}

	server := sshgate.New(config, c.ListenAddr)

	if err := server.ListenAndServe(context.Background()); err != nil {
		return err
	}

	return nil
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
