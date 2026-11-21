package main

import (
	"encoding/json"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"context"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/cli"
	"github.com/bingooyong/AIHostSecurityInspector/backend/internal/transport/ssh"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	args := os.Args[1:]
	if filepath.Base(os.Args[0]) == "hostsec-collector" {
		if orig := os.Getenv("SSH_ORIGINAL_COMMAND"); orig != "" {
			fields, err := ssh.ParseCollectorCommand(orig)
			if err != nil {
				_ = json.NewEncoder(os.Stderr).Encode(map[string]string{"level": "error", "code": "INVALID_ARGUMENT", "message": "remote collector command is rejected"})
				stop()
				os.Exit(2)
			}
			args = fields[1:]
		} else if len(args) == 0 || args[0] != "collect" {
			args = append([]string{"collect"}, args...)
		}
	}
	code := cli.Run(ctx, args, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
