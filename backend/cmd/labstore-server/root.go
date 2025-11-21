package main

import (
	"fmt"
	"strings"

	"github.com/IllumiKnowLabs/labstore/backend/internal/config"
	"github.com/IllumiKnowLabs/labstore/backend/internal/helper"
	"github.com/IllumiKnowLabs/labstore/backend/pkg/constants"
	"github.com/IllumiKnowLabs/labstore/backend/pkg/iam"
	"github.com/IllumiKnowLabs/labstore/backend/pkg/logger"
	"github.com/spf13/cobra"
)

func NewRootCmd() *cobra.Command {
	var cmd = &cobra.Command{
		Use:   fmt.Sprintf("%s-server", strings.ToLower(constants.Name)),
		Short: fmt.Sprintf("%s, by %s", constants.Name, constants.Author),
		Long:  fmt.Sprintf("%s - %s, by %s", constants.Name, constants.Description, constants.Author),

		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			fmt.Printf("🚀 Welcome to %s, by %s\n\n", constants.Name, constants.Author)

			debug := helper.Must(cmd.Flags().GetBool("debug"))
			logger.Init(logger.WithDebugFlag(debug))

			config.Load()
			iam.Load()
		},
	}

	cmd.PersistentFlags().Bool("debug", false, "Set debug level for logging")

	cmd.AddCommand(NewServeCmd())

	return cmd
}
