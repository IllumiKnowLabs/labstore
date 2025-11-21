package main

import (
	"github.com/IllumiKnowLabs/labstore/backend/internal/router"
	"github.com/spf13/cobra"
)

func NewServeCmd() *cobra.Command {
	var cmd = &cobra.Command{
		Use:   "serve",
		Short: "Run backend server",
		Run: func(cmd *cobra.Command, args []string) {
			router.Start()
		},
	}

	return cmd
}
