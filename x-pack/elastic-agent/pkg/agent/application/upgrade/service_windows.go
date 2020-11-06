// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// +build windows

package upgrade

import (
	"context"

	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/agent/errors"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/agent/install"
	"golang.org/x/sys/windows/svc/mgr"
)

// Init initializes os dependent properties.
func (ch *CrashChecker) Init(ctx context.Context) error {
	mgr, err := mgr.Connect()
	if err != nil {
		return errors.New("failed to initiate service manager", err)
	}

	ch.sc = &pidProvider{
		winManager: mgr,
	}

	return nil
}

type pidProvider struct {
	winManager *mgr.Mgr
}

func (p *pidProvider) Close() {}

func (p *pidProvider) PID(ctx context.Context) (int, error) {
	svc, err := p.winManager.OpenService(install.ServiceName)
	if err != nil {
		return 0, errors.New("filed to read windows service", err)
	}

	status, err := svc.Query()
	if err != nil {
		return 0, errors.New("filed to read windows service PID: %v", err)
	}

	return int(status.ProcessId), nil
}