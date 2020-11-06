// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/agent/application"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/agent/application/paths"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/agent/application/upgrade"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/agent/configuration"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/agent/errors"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/cli"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/core/logger"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/release"
)

const (
	// period during which we monitor for failures resulting in a rollback
	gracePeriodDuration = 10 * time.Minute

	watcherName = "elastic-agent-watcher"
)

func newWatchCommandWithArgs(flags *globalFlags, _ []string, streams *cli.IOStreams) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "watch",
		Short: "Watch watches Elastic Agent for failures and initiates rollback.",
		Long:  `Watch watches Elastic Agent for failures and initiates rollback.`,
		Run: func(c *cobra.Command, args []string) {
			if err := watchCmd(streams, c, flags, args); err != nil {
				fmt.Fprintf(streams.Err, "Error: %v\n", err)
				os.Exit(1)
			}
		},
	}

	return cmd
}

func watchCmd(streams *cli.IOStreams, cmd *cobra.Command, flags *globalFlags, args []string) error {
	log, err := configuredLogger(flags)
	if err != nil {
		return err
	}

	// TODO: remove me
	log.Debug("home", paths.Home())
	log.Debug("top", paths.Top())
	log.Debug("config", paths.Config())

	marker, err := upgrade.LoadMarker()
	if err != nil {
		log.Error("failed to load marker", err)
		return err
	}
	if marker == nil {
		// no marker found we're not in upgrade process
		log.Debugf("update marker not present at '%s'", filepath.Join(paths.Data(), ".update-marker"))
		return nil
	}

	locker := upgrade.NewLocker(paths.Top())
	if err := locker.TryLock(); err != nil {
		if err == upgrade.ErrAlreadyLocked {
			log.Debugf("exiting, lock already exist")
			return nil
		}

		log.Error("failed to acquire lock", err)
		return err
	}
	defer locker.Unlock()

	isWithinGrace, tilGrace := gracePeriod(marker)
	if !isWithinGrace {
		log.Debugf("not within grace [updatedOn %v] %v", marker.UpdatedOn.String(), time.Now().Sub(marker.UpdatedOn).String())
		// if it is started outside of upgrade loop
		// if we're not within grace and marker is still there it might mean
		// that cleanup was not performed ok, cleanup everything except current version
		// hash is the same as hash of agent which initiated watcher.
		upgrade.Cleanup(release.ShortCommit())
		// exit nicely
		return nil
	}
	// TODO: remove me
	log.Debugf("within grace [updatedOn %v] now: %v until end of grace: %v", marker.UpdatedOn, time.Now(), tilGrace.String())

	ctx := context.Background()

	if err := watch(ctx, tilGrace, log); err != nil {
		log.Debugf("Error detected proceeding to rollback", err)
		err = upgrade.Rollback(ctx, marker.PrevHash, marker.Hash)
		if err != nil {
			log.Error("rollback failed", err)
		}
		return err
	}

	err = upgrade.Cleanup(marker.Hash)
	if err != nil {
		log.Error("rollback failed", err)
	}
	return err
}

func watch(ctx context.Context, tilGrace time.Duration, log *logger.Logger) error {
	errChan := make(chan error)
	crashChan := make(chan error)

	ctx, cancel := context.WithCancel(ctx)

	//cleanup
	defer func() {
		cancel()
		close(errChan)
		close(crashChan)
	}()

	errorChecker, err := upgrade.NewErrorChecker(errChan, log)
	if err != nil {
		return err
	}

	crashChecker, err := upgrade.NewCrashChecker(ctx, errChan, log)
	if err != nil {
		return err
	}

	go errorChecker.Run(ctx)
	go crashChecker.Run(ctx)

WATCHLOOP:
	for {
		select {
		case <-ctx.Done():
			break WATCHLOOP
		// grace period passed, agent is considered stable
		case <-time.After(tilGrace):
			log.Info("Grace period passed, not watching")
			break WATCHLOOP
		// Agent in degraded state.
		case err := <-errChan:
			log.Error("Agent Error detected", err)
			return err
		// Agent keeps crashing unexpectedly
		case err := <-crashChan:
			log.Error("Agent crash detected", err)
			return err
		}
	}

	return nil
}

// gracePeriod returns true if it is within grace period and time until grace period ends.
// otherwise it returns false and 0
func gracePeriod(marker *upgrade.UpdateMarker) (bool, time.Duration) {
	sinceUpdate := time.Now().Sub(marker.UpdatedOn)

	if 0 < sinceUpdate && sinceUpdate < gracePeriodDuration {
		return true, gracePeriodDuration - sinceUpdate
	}

	return false, gracePeriodDuration
}

func configuredLogger(flags *globalFlags) (*logger.Logger, error) {
	pathConfigFile := flags.Config()
	rawConfig, err := application.LoadConfigFromFile(pathConfigFile)
	if err != nil {
		return nil, errors.New(err,
			fmt.Sprintf("could not read configuration file %s", pathConfigFile),
			errors.TypeFilesystem,
			errors.M(errors.MetaKeyPath, pathConfigFile))
	}

	cfg, err := configuration.NewFromConfig(rawConfig)
	if err != nil {
		return nil, errors.New(err,
			fmt.Sprintf("could not parse configuration file %s", pathConfigFile),
			errors.TypeFilesystem,
			errors.M(errors.MetaKeyPath, pathConfigFile))
	}

	cfg.Settings.LoggingConfig.Beat = watcherName

	logger, err := logger.NewFromConfig("", cfg.Settings.LoggingConfig)
	if err != nil {
		return nil, err
	}

	return logger, nil
}