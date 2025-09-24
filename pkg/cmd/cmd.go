package cmd

import (
	"context"
	"errors"
	"log/slog"
	"os"

	"github.com/alecthomas/kong"
	"github.com/cedws/sshgate/pkg/sshgate"
	"github.com/fsnotify/fsnotify"
)

type cli struct {
	ListenAddr string `help:"Address to listen on" default:":2222"`
	Ruleless   bool   `help:"Run in ruleless mode"`
	LogFormat  string `help:"Log format"`
	Config     string `help:"Path to JSON config file"`

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
		if err := serveUntilReload(context.Background(), cli); err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
	}
}

func serveUntilReload(ctx context.Context, cli *cli) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer watcher.Close()

	if err := watcher.Add(cli.Config); err != nil {
		return err
	}

	ctx, cancel := fsnotifyContext(ctx, watcher)
	defer cancel()

	return serve(ctx, cli)
}

func serve(ctx context.Context, c *cli) error {
	var opts []sshgate.Option
	if c.Ruleless {
		opts = append(opts, sshgate.WithRulelessMode())
	}

	config, err := sshgate.ReadConfig(c.Config)
	if err != nil {
		return err
	}

	server := sshgate.New(config, c.ListenAddr, opts...)
	return server.ListenAndServe(ctx)
}

func fsnotifyContext(ctx context.Context, watcher *fsnotify.Watcher) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(ctx)

	go func() {
		for {
			select {
			case evt := <-watcher.Events:
				if evt.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) != 0 {
					slog.Info("config file changed, reloading")
					cancel()
				}
			case <-watcher.Errors:
				cancel()
			case <-ctx.Done():
				return
			}
		}
	}()

	return ctx, cancel
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
