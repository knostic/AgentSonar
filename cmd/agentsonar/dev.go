//go:build dev

package main

import (
	"fmt"
	"os"

	"github.com/knostic/agentsonar"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(&cobra.Command{
		Use:   "nuke",
		Short: "Remove database and overrides (dev only)",
		Run: func(cmd *cobra.Command, args []string) {
			paths := []string{
				sai.DefaultDBPath(),
				sai.DefaultDBPath() + "-shm",
				sai.DefaultDBPath() + "-wal",
				sai.DefaultOverridesPath(),
			}
			for _, p := range paths {
				if err := os.Remove(p); err != nil {
					if os.IsNotExist(err) {
						continue
					}
					fmt.Fprintf(os.Stderr, "error: %v\n", err)
					os.Exit(1)
				}
				fmt.Printf("removed %s\n", p)
			}
		},
	})
}
