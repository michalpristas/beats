// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upgrade

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"time"

	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/agent/application/paths"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/release"
	"gopkg.in/yaml.v2"
)

const markerFilename = ".update-marker"

type updateMarker struct {
	// Version agent is updated to
	Version string `json:"version" yaml:"version"`
	// Hash agent is updated to
	Hash string `json:"hash" yaml:"hash"`
	//UpdatenOn marks a date when update happened
	UpdatenOn time.Time `json:"updated_on" yaml:"updated_on"`

	// PrevVersion is a version agent is updated from
	PrevVersion string `json:"prev_version" yaml:"prev_version"`
	// PrevHash is a hash agent is updated from
	PrevHash string `json:"prev_hash" yaml:"prev_hash"`
}

// markUpgrade marks update happened so we can handle grace period
func (h *Upgrader) markUpgrade(ctx context.Context, version, hash string) error {
	if err := updateHomePath(hash); err != nil {
		return err
	}

	prevVersion := release.Version()
	prevHash := release.Commit()
	if len(prevHash) > hashLen {
		prevHash = prevHash[:hashLen]
	}

	marker := updateMarker{
		Version:     version,
		Hash:        hash,
		UpdatenOn:   time.Now(),
		PrevVersion: prevVersion,
		PrevHash:    prevHash,
	}

	markerPath := filepath.Join(paths.Data(), markerFilename)
	markerBytes, err := json.Marshal(marker)
	if err != nil {
		return err
	}

	if err := ioutil.WriteFile(markerPath, markerBytes, 0600); err != nil {
		return err
	}

	activeCommitPath := filepath.Join(paths.Config(), agentCommitFile)
	return ioutil.WriteFile(activeCommitPath, []byte(hash), 0644)
}

func updateHomePath(hash string) error {
	pathsMap := make(map[string]string)
	pathsFilepath := filepath.Join(paths.Data(), "paths.yml")

	pathsBytes, err := ioutil.ReadFile(pathsFilepath)
	if err != nil {
		return err
	}

	if err := yaml.Unmarshal(pathsBytes, &pathsMap); err != nil {
		return err
	}

	pathsMap["path.home"] = filepath.Join(filepath.Dir(paths.Home()), fmt.Sprintf("%s-%s", agentName, hash)) //replace base with new hashed

	pathsBytes, err = yaml.Marshal(pathsMap)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(pathsFilepath, pathsBytes, 0740)
}
