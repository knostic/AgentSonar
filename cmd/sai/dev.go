//go:build dev

package main

import (
	"fmt"
	"os"

	"github.com/knostic/sai"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(&cobra.Command{
		Use:   "nuke",
		Short: "Remove database (dev only)",
		Run: func(cmd *cobra.Command, args []string) {
			path := sai.DefaultDBPath()
			if err := os.Remove(path); err != nil {
				if os.IsNotExist(err) {
					fmt.Println("database does not exist")
					return
				}
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("removed %s\n", path)
		},
	})
}
