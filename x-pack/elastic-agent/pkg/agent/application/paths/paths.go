// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package paths

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/config"
)

var (
	homePath    string
	configPath  string
	dataPath    string
	logsPath    string
	serviceName string
)

func init() {
	// is evaluated and point to versioned dir
	exePath := retrieveExecutablePath()
	initialHome := filepath.Dir(filepath.Dir(exePath)) // is two level up the executable

	fs := flag.CommandLine
	fs.StringVar(&homePath, "path.home", initialHome, "Agent root path")
	fs.StringVar(&configPath, "path.config", initialHome, "Config path is the directory Agent looks for its config file")
	fs.StringVar(&dataPath, "path.data", filepath.Join(initialHome, "data"), "Data path contains Agent managed binaries")
	fs.StringVar(&logsPath, "path.logs", initialHome, "Logs path contains Agent log output")

	getOverrides()
}

// UpdatePaths update paths based on changes in paths file.
func UpdatePaths() {
	getOverrides()
}

func getOverrides() {
	type paths struct {
		HomePath    string `config:"path.home" yaml:"path.home"`
		ConfigPath  string `config:"path.config" yaml:"path.config"`
		DataPath    string `config:"path.data" yaml:"path.data"`
		LogsPath    string `config:"path.logs" yaml:"path.logs"`
		ServiceName string `config:"path.service_name" yaml:"path.service_name"`
	}

	defaults := &paths{
		HomePath:   homePath,
		ConfigPath: configPath,
		DataPath:   dataPath,
		LogsPath:   logsPath,
	}

	pathsFile := filepath.Join(dataPath, "paths.yml")

	a, _ := filepath.Abs(pathsFile)
	fmt.Println(">>>>>> reading", a)
	rawConfig, err := config.LoadYAML(pathsFile)
	if err == nil {
		rawConfig.Unpack(defaults)
	}
	if err != nil {
		fmt.Println(">>>ERR: ", err)
	}

	fmt.Println(">>>>>> defaults", defaults)
	homePath = defaults.HomePath
	configPath = defaults.ConfigPath
	dataPath = defaults.DataPath
	logsPath = defaults.LogsPath
	serviceName = defaults.ServiceName
}

// ServiceName return predefined service name if defined by initial call.
func ServiceName() string {
	return serviceName
}

// Home returns a directory where binary lives
// Executable is not supported on nacl.
func Home() string {
	return homePath
}

// Config returns a directory where configuration file lives
func Config() string {
	return configPath
}

// Data returns the data directory for Agent
func Data() string {
	return dataPath
}

// Logs returns a the log directory for Agent
func Logs() string {
	return logsPath
}

func retrieveExecutablePath() string {
	execPath, err := os.Executable()
	if err != nil {
		panic(err)
	}

	evalPath, err := filepath.EvalSymlinks(execPath)
	if err != nil {
		panic(err)
	}

	return filepath.Dir(evalPath)
}
