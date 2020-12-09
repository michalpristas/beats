// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package application

import (
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/core/status"
)

type noopController struct{}

func (*noopController) Register() status.Reporter  { return &noopReporter{} }
func (*noopController) Status() status.AgentStatus { return status.Healthy }
func (*noopController) StatusString() string       { return "online" }

type noopReporter struct{}

func (*noopReporter) Update(status.AgentStatus) {}
func (*noopReporter) Unregister()               {}
