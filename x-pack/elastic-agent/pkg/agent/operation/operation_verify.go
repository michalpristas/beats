// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package operation

import (
	"context"
	"fmt"
	"os"

	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/agent/errors"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/agent/operation/config"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/artifact"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/artifact/download"
)

// operationVerify verifies downloaded artifact for correct signature
// skips if artifact is already installed
type operationVerify struct {
	eventProcessor callbackHooks
	program        Descriptor
	operatorConfig *config.Config
	verifier       download.Verifier
}

func newOperationVerify(
	program Descriptor,
	operatorConfig *config.Config,
	verifier download.Verifier,
	eventProcessor callbackHooks) *operationVerify {
	return &operationVerify{
		program:        program,
		operatorConfig: operatorConfig,
		eventProcessor: eventProcessor,
		verifier:       verifier,
	}
}

// Name is human readable name identifying an operation
func (o *operationVerify) Name() string {
	return "operation-verify"
}

// Check checks whether operation needs to be run
// examples:
// - Start does not need to run if process is running
// - Fetch does not need to run if package is already present
func (o *operationVerify) Check() (bool, error) {
	downloadConfig := o.operatorConfig.DownloadConfig
	fullPath, err := artifact.GetArtifactPath(o.program.BinaryName(), o.program.Version(), downloadConfig.OS(), downloadConfig.Arch(), downloadConfig.TargetDirectory)
	if err != nil {
		return false, err
	}

	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		return false, errors.New(errors.TypeApplication,
			fmt.Sprintf("%s.%s package does not exist in %s. Skipping operation %s", o.program.BinaryName(), o.program.Version(), fullPath, o.Name()))
	}

	return true, err
}

// Run runs the operation
func (o *operationVerify) Run(ctx context.Context, application Application) (err error) {
	defer func() {
		if err != nil {
			err = errors.New(err,
				o.Name(),
				errors.TypeApplication,
				errors.M(errors.MetaKeyAppName, application.Name()))
			o.eventProcessor.OnFailing(ctx, application.Name(), err)
		}
	}()

	isVerified, err := o.verifier.Verify(o.program.BinaryName(), o.program.Version())
	if err != nil {
		return errors.New(err,
			fmt.Sprintf("operation '%s' failed to verify %s.%s", o.Name(), o.program.BinaryName(), o.program.Version()),
			errors.TypeSecurity)
	}

	if !isVerified {
		return errors.New(err,
			fmt.Sprintf("operation '%s' marked '%s.%s' invalid", o.Name(), o.program.BinaryName(), o.program.Version()),
			errors.TypeSecurity)
	}

	return nil
}
