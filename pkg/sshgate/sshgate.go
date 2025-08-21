package sshgate

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

const fingerprintKey = "fingerprint"

type rejectionError struct {
	reason  ssh.RejectionReason
	message string
}

func (r rejectionError) Error() string {
	return r.message
}

func readString(r *bytes.Reader) (string, error) {
	var len uint32
	if err := binary.Read(r, binary.BigEndian, &len); err != nil {
		return "", err
	}

	buf := make([]byte, len)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}

	return string(buf), nil
}

func readUint32(r *bytes.Reader) (uint32, error) {
	var v uint32
	if err := binary.Read(r, binary.BigEndian, &v); err != nil {
		return 0, err
	}
	return v, nil
}

type directTCPIPExtraData struct {
	DestHost   string
	DestPort   int
	SourceHost string
	SourcePort int
}

func (d *directTCPIPExtraData) UnmarshalBinary(b []byte) error {
	r := bytes.NewReader(b)

	destHost, err := readString(r)
	if err != nil {
		return err
	}

	destPort, err := readUint32(r)
	if err != nil {
		return err
	}

	sourceHost, err := readString(r)
	if err != nil {
		return err
	}

	sourcePort, err := readUint32(r)
	if err != nil {
		return err
	}

	d.DestHost = destHost
	d.DestPort = int(destPort)
	d.SourceHost = sourceHost
	d.SourcePort = int(sourcePort)

	return nil
}

type Server struct {
	config     *Config
	listenAddr string
	conns      atomic.Int32
}

func New(config *Config, listenAddr string) *Server {
	return &Server{
		config:     config,
		listenAddr: listenAddr,
	}
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	sshConfig := &ssh.ServerConfig{
		PublicKeyCallback: s.pubkeyCallback,
	}

	var signers []ssh.Signer
	if copy(signers, s.config.signers) == 0 {
		slog.Warn("no host keys provided in config, generating ephemeral ed25519 host key")

		signer, err := generateSigner()
		if err != nil {
			return err
		}

		signers = append(signers, signer)
	}
	for _, signer := range signers {
		sshConfig.AddHostKey(signer)
	}

	listener, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return err
	}
	defer listener.Close()

	slog.Info("listening", "addr", s.listenAddr)

	go func() {
		for {
			select {
			case <-time.After(time.Second * 30):
				slog.Info("server status", "conns", s.conns.Load(), "goroutines", runtime.NumGoroutine())
			case <-ctx.Done():
				return
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		tcpConn, err := listener.Accept()
		if err != nil {
			slog.Error("error accepting connection",
				slog.String("addr", tcpConn.RemoteAddr().String()),
			)
			continue
		}

		go s.handleConnection(ctx, tcpConn, sshConfig)
	}
}

func (s *Server) pubkeyCallback(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	fingerprint := ssh.FingerprintSHA256(key)

	logger := slog.With(
		slog.Group(
			"conn",
			slog.String("addr", meta.RemoteAddr().String()),
			slog.String("fingerprint", fingerprint),
		),
	)

	logger.Info("client tries auth")

	if _, ok := s.config.identityRulesets[fingerprint]; !ok {
		// No rulesets for this fingerprint, let client try another
		logger.Info("no rulesets for this pubkey")
		return nil, fmt.Errorf("connection rejected")
	}

	logger.Info("found rulesets for pubkey")

	perms := &ssh.Permissions{
		Extensions: map[string]string{
			fingerprintKey: fingerprint,
		},
	}

	return perms, nil
}

func (s *Server) handleConnection(ctx context.Context, c net.Conn, config *ssh.ServerConfig) {
	sshConn, channels, requests, err := ssh.NewServerConn(c, config)
	if err != nil {
		c.Close()
		return
	}
	defer sshConn.Close()

	logger := slog.With(
		slog.Group("conn",
			slog.String("addr", sshConn.RemoteAddr().String()),
		),
	)

	logger.Info("new connection")

	s.conns.Add(1)
	defer s.conns.Add(-1)

	go func() {
		for req := range requests {
			req.Reply(false, nil)
		}
	}()

	for newChannel := range channels {
		go s.handleChannel(ctx, logger, sshConn, newChannel)
	}
}

func (s *Server) handleChannel(ctx context.Context, logger *slog.Logger, sshConn *ssh.ServerConn, newChannel ssh.NewChannel) {
	var err error

	switch channelType := newChannel.ChannelType(); channelType {
	case "direct-tcpip":
		err = s.handleDirectTCPIP(ctx, logger, sshConn, newChannel)
	default:
		err = rejectionError{
			ssh.UnknownChannelType,
			fmt.Sprintf("unsupported channel type %s", channelType),
		}
	}

	var rejection rejectionError
	if errors.As(err, &rejection) {
		logger.Info(
			"connection rejected",
			slog.String("reason", rejection.reason.String()),
			slog.String("message", rejection.message),
		)
		newChannel.Reject(rejection.reason, rejection.message)
		return
	}

	if err != nil {
		logger.Info(
			"error handling connection",
			slog.String("error", err.Error()),
		)
	}
}

func (s *Server) handleDirectTCPIP(ctx context.Context, logger *slog.Logger, sshConn *ssh.ServerConn, newChannel ssh.NewChannel) error {
	var extraData directTCPIPExtraData
	if err := extraData.UnmarshalBinary(newChannel.ExtraData()); err != nil {
		return rejectionError{ssh.ConnectionFailed, err.Error()}
	}
	var (
		destHost = extraData.DestHost
		destPort = extraData.DestPort
	)

	logger = logger.With(
		slog.Group(
			"dest",
			slog.String("host", destHost),
			slog.Int("port", destPort),
		),
	)

	if sshConn.Permissions == nil {
		return rejectionError{ssh.Prohibited, "connection rejected"}
	}
	fingerprint, ok := sshConn.Permissions.Extensions[fingerprintKey]
	if !ok {
		panic("expected fingerprint extension on new channel")
	}

	allowed, err := s.connAllowed(logger, fingerprint, destHost, destPort)
	if !allowed || err != nil {
		if err != nil {
			logger.Error(
				"error checking if remote conn is allowed",
				slog.String("error", err.Error()),
			)
		}

		return rejectionError{ssh.Prohibited, "remote connection rejected"}
	}

	remoteAddr := net.JoinHostPort(destHost, strconv.Itoa(destPort))

	// Remote connection allowed
	return s.dialRemote(ctx, logger, newChannel, remoteAddr)
}

func (s *Server) dialRemote(ctx context.Context, logger *slog.Logger, newChannel ssh.NewChannel, remoteAddr string) error {
	logger.Info("dialing remote")

	dialer := net.Dialer{}
	remoteConn, err := dialer.DialContext(ctx, "tcp", remoteAddr)
	if err != nil {
		return rejectionError{ssh.ConnectionFailed, "dial remote failed"}
	}
	defer remoteConn.Close()

	channelConn, reqs, err := newChannel.Accept()
	if err != nil {
		return fmt.Errorf("error accepting new channel: %w", err)
	}
	go ssh.DiscardRequests(reqs)

	s.forwardConns(channelConn, remoteConn)

	logger.Info("client disconnected")

	return nil
}

func (s *Server) forwardConns(sshConn, remoteConn io.ReadWriteCloser) {
	var wg sync.WaitGroup

	wg.Go(func() {
		io.Copy(sshConn, remoteConn)
		sshConn.Close()
	})

	wg.Go(func() {
		io.Copy(remoteConn, sshConn)
		remoteConn.Close()
	})

	wg.Wait()
}

func (s *Server) connAllowed(logger *slog.Logger, fingerprint, destHost string, destPort int) (bool, error) {
	rulesets, ok := s.config.identityRulesets[fingerprint]
	if !ok {
		panic("allowed previous connection but no rulesets")
	}

	destHostSpec, err := tryParseHostSpec(destHost)
	if err != nil {
		return false, err
	}

	for _, ruleset := range rulesets {
		if ruleset.Matches(destHostSpec, destPort) {
			logger.Info("remote connection allowed due to matching ruleset")
			return true, nil
		}
	}

	logger.Info("remote connection rejected because no rulesets permitted it")

	return false, nil
}
