// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package capabilities

import (
	"testing"

	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/core/logger"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/fleetapi"
	"github.com/stretchr/testify/assert"
)

func TestUpgrade(t *testing.T) {
	tr := &testReporter{}
	l, _ := logger.New("test")
	t.Run("invalid rule", func(t *testing.T) {
		r := &inputCapability{}
		cap, err := newUpgradeCapability(l, r, tr)
		assert.NoError(t, err, "no error expected")
		assert.Nil(t, cap, "cap should not be created")
	})

	t.Run("empty eql", func(t *testing.T) {
		r := &upgradeCapability{
			Type:                 "allow",
			UpgradeEqlDefinition: "",
		}
		cap, err := newUpgradeCapability(l, r, tr)
		assert.NoError(t, err, "error not expected, provided eql is valid")
		assert.NotNil(t, cap, "cap should be created")
	})

	t.Run("valid action - version match", func(t *testing.T) {
		r := &upgradeCapability{
			Type:                 "allow",
			UpgradeEqlDefinition: "${version} == '8.0.0'",
		}
		cap, err := newUpgradeCapability(l, r, tr)
		assert.NoError(t, err, "error not expected, provided eql is valid")
		assert.NotNil(t, cap, "cap should be created")

		ta := &testUpgradeAction{version: "8.0.0"}
		isBlocking, outAfter := cap.Apply(ta)

		assert.False(t, isBlocking, "should not be blocking")
		assert.Equal(t, ta, outAfter)
	})

	t.Run("valid action - deny version match", func(t *testing.T) {
		r := &upgradeCapability{
			Type:                 "deny",
			UpgradeEqlDefinition: "${version} == '8.0.0'",
		}
		cap, err := newUpgradeCapability(l, r, tr)
		assert.NoError(t, err, "error not expected, provided eql is valid")
		assert.NotNil(t, cap, "cap should be created")

		ta := &testUpgradeAction{version: "8.0.0"}
		isBlocking, outAfter := cap.Apply(ta)

		assert.True(t, isBlocking, "should not be blocking")
		assert.Equal(t, ta, outAfter)
	})

	t.Run("valid action - deny version match", func(t *testing.T) {
		r := &upgradeCapability{
			Type:                 "deny",
			UpgradeEqlDefinition: "${version} == '8.*.*'",
		}
		cap, err := newUpgradeCapability(l, r, tr)
		assert.NoError(t, err, "error not expected, provided eql is valid")
		assert.NotNil(t, cap, "cap should be created")

		ta := &testUpgradeAction{version: "9.0.0"}
		isBlocking, outAfter := cap.Apply(ta)

		assert.False(t, isBlocking, "should not be blocking")
		assert.Equal(t, ta, outAfter)
	})

	t.Run("valid action - version mismmatch", func(t *testing.T) {
		r := &upgradeCapability{
			Type:                 "allow",
			UpgradeEqlDefinition: "${version} == '7.12.0'",
		}
		cap, err := newUpgradeCapability(l, r, tr)
		assert.NoError(t, err, "error not expected, provided eql is valid")
		assert.NotNil(t, cap, "cap should be created")

		ta := &testUpgradeAction{version: "8.0.0"}
		isBlocking, outAfter := cap.Apply(ta)

		assert.True(t, isBlocking, "should not be blocking")
		assert.Equal(t, ta, outAfter)
	})

	t.Run("valid action - version bug allowed minor mismatch", func(t *testing.T) {
		r := &upgradeCapability{
			Type:                 "allow",
			UpgradeEqlDefinition: "match(${version}, '8.0.*')",
		}
		cap, err := newUpgradeCapability(l, r, tr)
		assert.NoError(t, err, "error not expected, provided eql is valid")
		assert.NotNil(t, cap, "cap should be created")

		ta := &testUpgradeAction{version: "8.1.0"}
		isBlocking, outAfter := cap.Apply(ta)

		assert.True(t, isBlocking, "should not be blocking")
		assert.Equal(t, ta, outAfter)
	})

	t.Run("valid action - version minor allowed major mismatch", func(t *testing.T) {
		r := &upgradeCapability{
			Type:                 "allow",
			UpgradeEqlDefinition: "match(${version}, '8.*.*')",
		}
		cap, err := newUpgradeCapability(l, r, tr)
		assert.NoError(t, err, "error not expected, provided eql is valid")
		assert.NotNil(t, cap, "cap should be created")

		ta := &testUpgradeAction{version: "7.157.0"}
		isBlocking, outAfter := cap.Apply(ta)

		assert.True(t, isBlocking, "should not be blocking")
		assert.Equal(t, ta, outAfter)
	})

	t.Run("valid action - version minor allowed minor upgrade", func(t *testing.T) {
		r := &upgradeCapability{
			Type:                 "allow",
			UpgradeEqlDefinition: "match(${version}, '8.*.*')",
		}
		cap, err := newUpgradeCapability(l, r, tr)
		assert.NoError(t, err, "error not expected, provided eql is valid")
		assert.NotNil(t, cap, "cap should be created")

		ta := &testUpgradeAction{version: "8.2.0"}
		isBlocking, outAfter := cap.Apply(ta)

		assert.False(t, isBlocking, "should not be blocking")
		assert.Equal(t, ta, outAfter)
	})

	t.Run("valid fleetatpi.action - version match", func(t *testing.T) {
		r := &upgradeCapability{
			Type:                 "allow",
			UpgradeEqlDefinition: "match(${version}, '8.*.*')",
		}
		cap, err := newUpgradeCapability(l, r, tr)
		assert.NoError(t, err, "error not expected, provided eql is valid")
		assert.NotNil(t, cap, "cap should be created")

		apiAction := fleetapi.ActionUpgrade{
			ActionID:   "",
			ActionType: "",
			Version:    "8.2.0",
			SourceURI:  "http://artifacts.elastic.co",
		}
		isBlocking, outAfter := cap.Apply(apiAction)

		assert.False(t, isBlocking, "should not be blocking")
		assert.Equal(t, apiAction, outAfter, "action should not be altered")
	})

	t.Run("valid fleetatpi.action - version mismmatch", func(t *testing.T) {
		r := &upgradeCapability{
			Type:                 "allow",
			UpgradeEqlDefinition: "match(${version}, '8.*.*')",
		}
		cap, err := newUpgradeCapability(l, r, tr)
		assert.NoError(t, err, "error not expected, provided eql is valid")
		assert.NotNil(t, cap, "cap should be created")

		apiAction := &fleetapi.ActionUpgrade{
			Version:   "9.0.0",
			SourceURI: "http://artifacts.elastic.co",
		}
		isBlocking, outAfter := cap.Apply(apiAction)

		assert.True(t, isBlocking, "should not be blocking")
		assert.Equal(t, apiAction, outAfter, "action should not be altered")
	})

	t.Run("valid fleetatpi.action - version mismmatch", func(t *testing.T) {
		r := &upgradeCapability{
			Type:                 "allow",
			UpgradeEqlDefinition: "match(${version}, '8.*.*')",
		}
		cap, err := newUpgradeCapability(l, r, tr)
		assert.NoError(t, err, "error not expected, provided eql is valid")
		assert.NotNil(t, cap, "cap should be created")

		apiAction := fleetapi.ActionUpgrade{
			Version:   "9.0.0",
			SourceURI: "http://artifacts.elastic.co",
		}
		isBlocking, outAfter := cap.Apply(apiAction)

		assert.True(t, isBlocking, "should not be blocking")
		assert.Equal(t, apiAction, outAfter, "action should not be altered")
	})

	t.Run("valid action - source uri trusted", func(t *testing.T) {
		r := &upgradeCapability{
			Type:                 "allow",
			UpgradeEqlDefinition: "startsWith(${source_uri}, 'https')",
		}
		cap, err := newUpgradeCapability(l, r, tr)
		assert.NoError(t, err, "error not expected, provided eql is valid")
		assert.NotNil(t, cap, "cap should be created")

		apiAction := fleetapi.ActionUpgrade{
			Version:   "9.0.0",
			SourceURI: "https://artifacts.elastic.co",
		}
		isBlocking, outAfter := cap.Apply(apiAction)

		assert.False(t, isBlocking, "should not be blocking")
		assert.Equal(t, apiAction, outAfter, "action should not be altered")
	})

	t.Run("valid action - source uri untrusted", func(t *testing.T) {
		r := &upgradeCapability{
			Type:                 "allow",
			UpgradeEqlDefinition: "startsWith(${source_uri}, 'https')",
		}
		cap, err := newUpgradeCapability(l, r, tr)
		assert.NoError(t, err, "error not expected, provided eql is valid")
		assert.NotNil(t, cap, "cap should be created")

		apiAction := fleetapi.ActionUpgrade{
			Version:   "9.0.0",
			SourceURI: "http://artifacts.elastic.co",
		}
		isBlocking, outAfter := cap.Apply(apiAction)

		assert.True(t, isBlocking, "should not be blocking")
		assert.Equal(t, apiAction, outAfter, "action should not be altered")
	})

	t.Run("unknown action", func(t *testing.T) {
		r := &upgradeCapability{
			Type:                 "allow",
			UpgradeEqlDefinition: "startsWith(${source_uri}, 'https')",
		}
		cap, err := newUpgradeCapability(l, r, tr)
		assert.NoError(t, err, "error not expected, provided eql is valid")
		assert.NotNil(t, cap, "cap should be created")

		apiAction := fleetapi.ActionPolicyChange{}
		isBlocking, outAfter := cap.Apply(apiAction)

		assert.False(t, isBlocking, "should not be blocking")
		assert.Equal(t, apiAction, outAfter, "action should not be altered")
	})
}

type testUpgradeAction struct {
	version string
}

// Version to upgrade to.
func (a *testUpgradeAction) Version() string {
	return a.version
}

// SourceURI for download.
func (a *testUpgradeAction) SourceURI() string {
	return "http://artifacts.elastic.co"
}
