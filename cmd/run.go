/*
Copyright © 2022 Nik Ogura <nik@orionlabs.io>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"github.com/orion-labs/tlssync/pkg/tlssync"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var filePath string

// runCmd represents the run command
var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run the TLS Sync Service",
	Long: `
Run the TLS Sync Service`,
	Run: func(cmd *cobra.Command, args []string) {
		if filePath == "" {
			log.Fatalf("Cannot run without config file (-f).")
		}

		files, err := tlssync.LoadConfig(filePath)
		if err != nil {
			log.Fatalf("Failed to load config file %s: %s", filePath, err)
		}

		ts, err := tlssync.NewTlsSync(files)
		if err != nil {
			log.Fatalf("Failed to create Sync: %s", err)
		}

		err = ts.MonitorSecrets()
		if err != nil {
			log.Fatalf("Secret monitoring failed: %s", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(runCmd)

	runCmd.Flags().StringVarP(&filePath, "file", "f", "", "path to config file")
}
