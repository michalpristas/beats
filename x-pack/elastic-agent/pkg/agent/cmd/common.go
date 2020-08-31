// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package cmd

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"

	// import logp flags
	_ "github.com/elastic/beats/v7/libbeat/logp/configure"

	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/agent/application/paths"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/basecmd"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/cli"
)

const (
	defaultConfig = "elastic-agent.yml"
	hashLen       = 6
	commitFile    = ".elastic-agent.active.commit"
)

type globalFlags struct {
	PathConfigFile string
}

// Config returns path which identifies configuration file.
func (f *globalFlags) Config() string {
	if len(f.PathConfigFile) == 0 || f.PathConfigFile == defaultConfig {
		return filepath.Join(paths.Config(), defaultConfig)
	}
	return f.PathConfigFile
}

// NewCommand returns the default command for the agent.
func NewCommand() *cobra.Command {
	return NewCommandWithArgs(os.Args, cli.NewIOStreams())
}

// NewCommandWithArgs returns a new agent with the flags and the subcommand.
func NewCommandWithArgs(args []string, streams *cli.IOStreams) *cobra.Command {
	cmd := &cobra.Command{
		Use: "elastic-agent [subcommand]",
	}

	flags := &globalFlags{}

	// path flags
	cmd.PersistentFlags().AddGoFlag(flag.CommandLine.Lookup("path.home"))
	cmd.PersistentFlags().AddGoFlag(flag.CommandLine.Lookup("path.config"))
	cmd.PersistentFlags().AddGoFlag(flag.CommandLine.Lookup("path.data"))
	cmd.PersistentFlags().AddGoFlag(flag.CommandLine.Lookup("path.logs"))
	cmd.PersistentFlags().StringVarP(&flags.PathConfigFile, "c", "c", defaultConfig, `Configuration file, relative to path.config`)

	// logging flags
	cmd.PersistentFlags().AddGoFlag(flag.CommandLine.Lookup("v"))
	cmd.PersistentFlags().AddGoFlag(flag.CommandLine.Lookup("e"))
	cmd.PersistentFlags().AddGoFlag(flag.CommandLine.Lookup("d"))
	cmd.PersistentFlags().AddGoFlag(flag.CommandLine.Lookup("environment"))

	// sub-commands
	run := newRunCommandWithArgs(flags, args, streams)
	cmd.AddCommand(basecmd.NewDefaultCommandsWithArgs(args, streams)...)
	cmd.AddCommand(run)
	cmd.AddCommand(newEnrollCommandWithArgs(flags, args, streams))
	cmd.AddCommand(newIntrospectCommandWithArgs(flags, args, streams))

	// windows special hidden sub-command (only added on windows)
	reexec := newReExecWindowsCommand(flags, args, streams)
	if reexec != nil {
		cmd.AddCommand(reexec)
	}
	cmd.PersistentPreRunE = preRunCheck(flags)
	cmd.Run = run.Run

	return cmd
}

func hashedDirName(filecontent []byte) string {
	s := strings.TrimSpace(string(filecontent))
	if len(s) == 0 {
		return "elastic-agent"
	}

	s = smallHash(s)

	return fmt.Sprintf("elastic-agent-%s", s)
}

func smallHash(hash string) string {
	if len(hash) > hashLen {
		hash = hash[:hashLen]
	}

	return hash
}

func generatePaths(dir, origExec string) error {
	pathsCfg := map[string]interface{}{
		"path.data":         paths.Data(),
		"path.home":         dir,
		"path.config":       paths.Config(),
		"path.service_name": origExec,
	}

	pathsCfgPath := filepath.Join(paths.Data(), "paths.yml")
	pathsContent, err := yaml.Marshal(pathsCfg)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(pathsCfgPath, pathsContent, 0740)
}
