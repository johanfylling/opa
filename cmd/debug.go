// Copyright 2024 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package cmd

import (
	"context"
	"fmt"
	"net"

	"github.com/open-policy-agent/opa/debug"
	"github.com/open-policy-agent/opa/logging"
	"github.com/spf13/cobra"
)

type debugParams struct {
	server  bool
	address string
	logger  logging.Logger
}

func newDebugParams() debugParams {
	logger := logging.New()
	logger.SetLevel(logging.Debug)
	return debugParams{
		logger: logger,
	}
}

func init() {
	params := newDebugParams()

	debugCommand := &cobra.Command{
		Use:   "debug",
		Short: "Debug OPA",
		Long:  "Debug OPA.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return startDebugger(context.Background(), params)
		},
	}

	debugCommand.Flags().BoolVarP(&params.server, "server", "s", false, "Run debugger in server mode.")
	debugCommand.Flags().StringVar(&params.address, "address", "localhost:4712", "Address to listen on.")
	RootCommand.AddCommand(debugCommand)
}

func startDebugger(ctx context.Context, params debugParams) error {
	if !params.server {
		return fmt.Errorf("debugger must be run in server mode")
	}

	listener, err := net.Listen("tcp", params.address)
	if err != nil {
		return fmt.Errorf("failed to setup server listener: %v", err)
	}
	params.logger.Info("Listening on %s", params.address)

	for {
		params.logger.Debug("Waiting for connections...")
		conn, err := listener.Accept()
		if err != nil {
			panic(err)
		}

		go func() {
			d := debug.NewDebugger(debug.Logger(params.logger))
			if err := handleConnection(ctx, conn, d, params.logger); err != nil {
				params.logger.Warn("Connection failed: %v", err)
			}
		}()
	}

	return nil
}

func handleConnection(ctx context.Context, conn net.Conn, d *debug.Debugger, logger logging.Logger) error {
	defer func() {
		logger.Info("Closing connection")
		if err := conn.Close(); err != nil {
			fmt.Println(err)
		}
	}()

	return d.Start(ctx, conn)
}
