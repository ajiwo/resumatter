package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	// Version information - can be set during build with ldflags
	Version   = "dev"
	GitCommit = "unknown"
	BuildDate = "unknown"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Long:  "Print version information for resumatter",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("resumatter version %s\n", Version)
		fmt.Printf("Git commit: %s\n", GitCommit)
		fmt.Printf("Build date: %s\n", BuildDate)
	},
}
