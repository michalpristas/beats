// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package install

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/kardianos/service"

	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/agent/application/info"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/agent/application/paths"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/agent/errors"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/agent/program"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/agent/transpiler"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/artifact/uninstall"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/config"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/config/operations"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/release"
)

// Uninstall uninstalls persistently Elastic Agent on the system.
func Uninstall(cfgFile string) error {
	// uninstall the current service
	svc, err := newService()
	if err != nil {
		return err
	}
	status, _ := svc.Status()
	if status == service.StatusRunning {
		err := svc.Stop()
		if err != nil {
			return errors.New(
				err,
				fmt.Sprintf("failed to stop service (%s)", paths.ServiceName),
				errors.M("service", paths.ServiceName))
		}
		status = service.StatusStopped
	}
	_ = svc.Uninstall()

	// remove, if present on platform
	if paths.ShellWrapperPath != "" {
		err = os.Remove(paths.ShellWrapperPath)
		if !os.IsNotExist(err) && err != nil {
			return errors.New(
				err,
				fmt.Sprintf("failed to remove shell wrapper (%s)", paths.ShellWrapperPath),
				errors.M("destination", paths.ShellWrapperPath))
		}
	}

	// remove existing directory
	err = os.RemoveAll(paths.InstallPath)
	if err != nil {
		if runtime.GOOS == "windows" {
			// possible to fail on Windows, because elastic-agent.exe is running from
			// this directory.
			return nil
		}
		return errors.New(
			err,
			fmt.Sprintf("failed to remove installation directory (%s)", paths.InstallPath),
			errors.M("directory", paths.InstallPath))
	}

	return nil
}

// RemovePath helps with removal path where there is a probability
// of running into self which might prevent removal.
// Removal will be initiated 2 seconds after a call.
func RemovePath(path string) error {
	cleanupErr := os.RemoveAll(path)
	if cleanupErr != nil && isBlockingOnSelf(cleanupErr) {
		delayedRemoval(path)
	}

	return cleanupErr
}

func isBlockingOnSelf(err error) bool {
	// cannot remove self, this is expected on windows
	// fails with  remove {path}}\elastic-agent.exe: Access is denied
	return runtime.GOOS == "windows" &&
		err != nil &&
		strings.Contains(err.Error(), "elastic-agent.exe") &&
		strings.Contains(err.Error(), "Access is denied")
}

func delayedRemoval(path string) {
	// The installation path will still exists because we are executing from that
	// directory. So cmd.exe is spawned that sleeps for 2 seconds (using ping, recommend way from
	// from Windows) then rmdir is performed.
	rmdir := exec.Command(
		filepath.Join(os.Getenv("windir"), "system32", "cmd.exe"),
		"/C", "ping", "-n", "2", "127.0.0.1", "&&", "rmdir", "/s", "/q", path)
	_ = rmdir.Start()

}

func uninstallPrograms(ctx context.Context, cfgFile string) error {
	cfg, err := operations.LoadFullAgentConfig(cfgFile)
	if err != nil {
		return err
	}

	pp, err := programsFromConfig(cfg)
	if err != nil {
		return err
	}

	uninstaller, err := uninstall.NewUninstaller()
	if err != nil {
		return err
	}

	for _, p := range pp {
		if err := uninstaller.Uninstall(ctx, p.Spec, release.Version(), paths.InstallPath); err != nil {
			fmt.Printf("failed to uninstall '%s': %v", p.Spec.Name, err)
		}
	}

	return nil
}

func programsFromConfig(cfg *config.Config) ([]program.Program, error) {
	mm, err := cfg.ToMapStr()
	if err != nil {
		return nil, errors.New("failed to create a map from config", err)
	}
	ast, err := transpiler.NewAST(mm)
	if err != nil {
		return nil, errors.New("failed to create a ast from config", err)
	}

	agentInfo, err := info.NewAgentInfo()
	if err != nil {
		return nil, errors.New("failed to get an agent info", err)
	}

	ppMap, err := program.Programs(agentInfo, ast)

	var pp []program.Program
	check := make(map[string]bool)

	for _, v := range ppMap {
		for _, p := range v {
			if _, found := check[p.Spec.Cmd]; found {
				continue
			}

			pp = append(pp, p)
			check[p.Spec.Cmd] = true
		}
	}

	return pp, nil
}
