package main

import "github.com/IllumiKnowLabs/labstore/backend/internal/helper"

func main() {
	rootCmd := NewRootCmd()
	helper.CheckFatal(rootCmd.Execute())
}
