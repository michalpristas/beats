// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package application

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/elastic/go-sysinfo"

	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/agent/application/filters"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/agent/application/gateway"
	fleetgateway "github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/agent/application/gateway/fleet"
	localgateway "github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/agent/application/gateway/fleetserver"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/agent/application/info"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/agent/application/paths"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/agent/application/pipeline"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/agent/application/pipeline/actions/handlers"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/agent/application/pipeline/dispatcher"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/agent/application/pipeline/emitter"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/agent/application/pipeline/emitter/modifiers"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/agent/application/pipeline/router"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/agent/application/pipeline/stream"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/agent/application/upgrade"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/agent/configuration"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/agent/errors"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/agent/operation"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/agent/storage"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/agent/storage/store"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/capabilities"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/composable"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/config"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/core/logger"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/core/monitoring"

	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/core/server"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/core/status"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/fleetapi"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/fleetapi/acker/fleet"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/fleetapi/acker/lazy"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/fleetapi/client"
	reporting "github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/reporter"
	fleetreporter "github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/reporter/fleet"
	logreporter "github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/reporter/log"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/sorted"
)

type stateStore interface {
	Add(fleetapi.Action)
	AckToken() string
	SetAckToken(ackToken string)
	Save() error
	Actions() []fleetapi.Action
}

// Managed application, when the application is run in managed mode, most of the configuration are
// coming from the Fleet App.
type Managed struct {
	bgContext   context.Context
	cancelCtxFn context.CancelFunc
	log         *logger.Logger
	Config      configuration.FleetAgentConfig
	agentInfo   *info.AgentInfo
	gateway     gateway.FleetGateway
	router      pipeline.Router
	srv         *server.Server
	stateStore  stateStore
	upgrader    *upgrade.Upgrader
}

func newManaged(
	ctx context.Context,
	log *logger.Logger,
	storeSaver storage.Store,
	cfg *configuration.Configuration,
	rawConfig *config.Config,
	reexec reexecManager,
	statusCtrl status.Controller,
	agentInfo *info.AgentInfo,
) (*Managed, error) {
	checkBinary(log, "nm.1")
	caps, err := capabilities.Load(paths.AgentCapabilitiesPath(), log, statusCtrl)
	if err != nil {
		return nil, err
	}

	checkBinary(log, "nm.2")
	client, err := client.NewAuthWithConfig(log, cfg.Fleet.AccessAPIKey, cfg.Fleet.Client)
	if err != nil {
		return nil, errors.New(err,
			"fail to create API client",
			errors.TypeNetwork,
			errors.M(errors.MetaKeyURI, cfg.Fleet.Client.Host))
	}

	checkBinary(log, "nm.3")
	sysInfo, err := sysinfo.Host()
	if err != nil {
		return nil, errors.New(err,
			"fail to get system information",
			errors.TypeUnexpected)
	}

	managedApplication := &Managed{
		log:       log,
		agentInfo: agentInfo,
	}

	checkBinary(log, "nm.4")
	managedApplication.bgContext, managedApplication.cancelCtxFn = context.WithCancel(ctx)
	managedApplication.srv, err = server.NewFromConfig(log, cfg.Settings.GRPC, &operation.ApplicationStatusHandler{})
	if err != nil {
		return nil, errors.New(err, "initialize GRPC listener", errors.TypeNetwork)
	}

	checkBinary(log, "nm.4")
	// must start before `Start` is called as Fleet will already try to start applications
	// before `Start` is even called.
	err = managedApplication.srv.Start()
	if err != nil {
		return nil, errors.New(err, "starting GRPC listener", errors.TypeNetwork)
	}

	checkBinary(log, "nm.5")
	logR := logreporter.NewReporter(log)

	checkBinary(log, "nm.6")
	fleetR, err := fleetreporter.NewReporter(agentInfo, log, cfg.Fleet.Reporting)
	if err != nil {
		return nil, errors.New(err, "fail to create reporters")
	}

	checkBinary(log, "nm.7")
	combinedReporter := reporting.NewReporter(managedApplication.bgContext, log, agentInfo, logR, fleetR)

	checkBinary(log, "nm.8")
	monitor, err := monitoring.NewMonitor(cfg.Settings)
	if err != nil {
		return nil, errors.New(err, "failed to initialize monitoring")
	}

	checkBinary(log, "nm.9")
	router, err := router.New(log, stream.Factory(managedApplication.bgContext, agentInfo, cfg.Settings, managedApplication.srv, combinedReporter, monitor, statusCtrl))
	if err != nil {
		return nil, errors.New(err, "fail to initialize pipeline router")
	}
	managedApplication.router = router

	checkBinary(log, "nm.10")
	composableCtrl, err := composable.New(log, rawConfig)
	if err != nil {
		return nil, errors.New(err, "failed to initialize composable controller")
	}

	checkBinary(log, "nm.11")
	emit, err := emitter.New(
		managedApplication.bgContext,
		log,
		agentInfo,
		composableCtrl,
		router,
		&pipeline.ConfigModifiers{
			Decorators: []pipeline.DecoratorFunc{modifiers.InjectMonitoring},
			Filters:    []pipeline.FilterFunc{filters.StreamChecker, modifiers.InjectFleet(rawConfig, sysInfo.Info(), agentInfo)},
		},
		caps,
		monitor,
	)
	if err != nil {
		return nil, err
	}
	checkBinary(log, "nm.12")
	acker, err := fleet.NewAcker(log, agentInfo, client)
	if err != nil {
		return nil, err
	}

	checkBinary(log, "nm.13")
	batchedAcker := lazy.NewAcker(acker, log)

	checkBinary(log, "nm.14")
	// Create the state store that will persist the last good policy change on disk.
	stateStore, err := store.NewStateStoreWithMigration(log, paths.AgentActionStoreFile(), paths.AgentStateStoreFile())
	if err != nil {
		return nil, errors.New(err, fmt.Sprintf("fail to read action store '%s'", paths.AgentActionStoreFile()))
	}

	checkBinary(log, "nm.15")
	managedApplication.stateStore = stateStore
	actionAcker := store.NewStateStoreActionAcker(batchedAcker, stateStore)

	checkBinary(log, "nm.16")
	actionDispatcher, err := dispatcher.New(managedApplication.bgContext, log, handlers.NewDefault(log))
	if err != nil {
		return nil, err
	}

	checkBinary(log, "nm.17")
	managedApplication.upgrader = upgrade.NewUpgrader(
		agentInfo,
		cfg.Settings.DownloadConfig,
		log,
		[]context.CancelFunc{managedApplication.cancelCtxFn},
		reexec,
		acker,
		combinedReporter,
		caps)

	policyChanger := handlers.NewPolicyChange(
		log,
		emit,
		agentInfo,
		cfg,
		storeSaver,
	)

	actionDispatcher.MustRegister(
		&fleetapi.ActionPolicyChange{},
		policyChanger,
	)

	actionDispatcher.MustRegister(
		&fleetapi.ActionPolicyReassign{},
		handlers.NewPolicyReassign(log),
	)

	actionDispatcher.MustRegister(
		&fleetapi.ActionUnenroll{},
		handlers.NewUnenroll(
			log,
			emit,
			router,
			[]context.CancelFunc{managedApplication.cancelCtxFn},
			stateStore,
		),
	)

	actionDispatcher.MustRegister(
		&fleetapi.ActionUpgrade{},
		handlers.NewUpgrade(log, managedApplication.upgrader),
	)

	actionDispatcher.MustRegister(
		&fleetapi.ActionSettings{},
		handlers.NewSettings(
			log,
			reexec,
			agentInfo,
		),
	)

	actionDispatcher.MustRegister(
		&fleetapi.ActionApp{},
		handlers.NewAppAction(log, managedApplication.srv),
	)

	actionDispatcher.MustRegister(
		&fleetapi.ActionUnknown{},
		handlers.NewUnknown(log),
	)

	actions := stateStore.Actions()
	stateRestored := false
	checkBinary(log, "nm.18")
	if len(actions) > 0 && !managedApplication.wasUnenrolled() {
		// TODO(ph) We will need an improvement on fleet, if there is an error while dispatching a
		// persisted action on disk we should be able to ask Fleet to get the latest configuration.
		// But at the moment this is not possible because the policy change was acked.
		if err := store.ReplayActions(log, actionDispatcher, actionAcker, actions...); err != nil {
			log.Errorf("could not recover state, error %+v, skipping...", err)
		}
		stateRestored = true
	}

	checkBinary(log, "nm.19")
	gateway, err := fleetgateway.New(
		managedApplication.bgContext,
		log,
		agentInfo,
		client,
		actionDispatcher,
		fleetR,
		actionAcker,
		statusCtrl,
		stateStore,
	)
	if err != nil {
		return nil, err
	}
	checkBinary(log, "nm.20")
	gateway, err = localgateway.New(managedApplication.bgContext, log, cfg.Fleet, rawConfig, gateway, emit, !stateRestored)
	if err != nil {
		return nil, err
	}
	checkBinary(log, "nm.21")
	// add the acker and gateway to setters, so the they can be updated
	// when the hosts for Fleet Server are updated by the policy.
	if cfg.Fleet.Server == nil {
		// setters only set when not running a local Fleet Server
		checkBinary(log, "nm.22")
		policyChanger.AddSetter(gateway)
		checkBinary(log, "nm.23")
		policyChanger.AddSetter(acker)
	}

	managedApplication.gateway = gateway
	return managedApplication, nil
}

// Routes returns a list of routes handled by agent.
func (m *Managed) Routes() *sorted.Set {
	return m.router.Routes()
}

// Start starts a managed elastic-agent.
func (m *Managed) Start() error {
	checkBinary(m.log, "s.1")
	m.log.Info("Agent is starting")
	if m.wasUnenrolled() {
		m.log.Warnf("agent was previously unenrolled. To reactivate please reconfigure or enroll again.")
		return nil
	}
	checkBinary(m.log, "s.2")
	// reload ID because of win7 sync issue
	if err := m.agentInfo.ReloadID(); err != nil {
		return err
	}

	checkBinary(m.log, "s.3")
	err := m.upgrader.Ack(m.bgContext)
	if err != nil {
		m.log.Warnf("failed to ack update %v", err)
	}
	checkBinary(m.log, "s.4")

	err = m.gateway.Start()
	if err != nil {
		return err
	}
	checkBinary(m.log, "s.5")
	return nil
}

// Stop stops a managed elastic-agent.
func (m *Managed) Stop() error {
	defer m.log.Info("Agent is stopped")
	m.cancelCtxFn()
	m.router.Shutdown()
	m.srv.Stop()
	return nil
}

// AgentInfo retrieves elastic-agent information.
func (m *Managed) AgentInfo() *info.AgentInfo {
	return m.agentInfo
}

func (m *Managed) wasUnenrolled() bool {
	actions := m.stateStore.Actions()
	for _, a := range actions {
		if a.Type() == "UNENROLL" {
			return true
		}
	}

	return false
}

func checkBinary(log *logger.Logger, point string) {
	pid := os.Getpid()
	fn := filepath.Join(paths.Top(), paths.BinaryName)
	_, err := os.Stat(fn)
	suffix := "ok"

	if os.IsNotExist(err) {
		suffix = "not found"
	}

	log.Errorf(">>> [%d].%s %s %s", point, pid, fn, suffix)
}
