// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package transpiler

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"gopkg.in/yaml.v2"
)

// StepList is a container that allow the same tree to be executed on multiple defined Step.
type StepList struct {
	Steps []Step
}

// Step is an execution step which needs to be run.
type Step interface {
	Execute(rootDir string) error
}

// Execute executes a list of steps.
func (r *StepList) Execute(rootDir string) error {
	var err error
	for _, step := range r.Steps {
		err = step.Execute(rootDir)
		if err != nil {
			return err
		}
	}

	return nil
}

// MarshalYAML marsharl a steps list to YAML.
func (r *StepList) MarshalYAML() (interface{}, error) {
	doc := make([]map[string]Step, 0, len(r.Steps))

	for _, step := range r.Steps {
		var name string
		switch step.(type) {
		case *DeleteFileStep:
			name = "delete_file"
		case *MoveFileStep:
			name = "move_file"

		default:
			return nil, fmt.Errorf("unknown rule of type %T", step)
		}

		subdoc := map[string]Step{
			name: step,
		}

		doc = append(doc, subdoc)
	}
	return doc, nil
}

// UnmarshalYAML unmarshal a YAML document into a RuleList.
func (r *StepList) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var unpackTo []map[string]interface{}

	err := unmarshal(&unpackTo)
	if err != nil {
		return err
	}

	// NOTE(ph): this is a bit of a hack because I want to make sure
	// the unpack strategy stay in the struct implementation and yaml
	// doesn't have a RawMessage similar to the JSON package, so partial unpack
	// is not possible.
	unpack := func(in interface{}, out interface{}) error {
		b, err := yaml.Marshal(in)
		if err != nil {
			return err
		}
		return yaml.Unmarshal(b, out)
	}

	var steps []Step

	for _, m := range unpackTo {
		ks := keys(m)
		if len(ks) > 1 {
			return fmt.Errorf("unknown rule identifier, expecting one identifier and received %d", len(ks))
		}

		name := ks[0]
		fields := m[name]

		var s Step
		switch name {
		case "delete_file":
			s = &DeleteFileStep{}
		case "move_file":
			s = &MoveFileStep{}
		default:
			return fmt.Errorf("unknown rule of type %s", name)
		}

		if err := unpack(fields, s); err != nil {
			return err
		}

		steps = append(steps, s)
	}
	r.Steps = steps
	return nil
}

// DeleteFileStep removes a file from disk.
type DeleteFileStep struct {
	Path string
	// FailOnMissing fails if file is already missing
	FailOnMissing bool
}

// Execute executes delete file step.
func (r *DeleteFileStep) Execute(rootDir string) error {
	path, isSubpath := joinPaths(rootDir, r.Path)
	if !isSubpath {
		return fmt.Errorf("invalid path value for operation 'Delete': %s", path)
	}

	err := os.Remove(path)

	if os.IsNotExist(err) && r.FailOnMissing {
		// is not found and should be reported
		return err
	}

	if err != nil && !os.IsNotExist(err) {
		// report others
		return err
	}

	return nil
}

// DeleteFile creates a DeleteFileStep
func DeleteFile(path string, failOnMissing bool) *DeleteFileStep {
	return &DeleteFileStep{
		Path:          path,
		FailOnMissing: failOnMissing,
	}
}

// MoveFileStep moves a file to a new location.
type MoveFileStep struct {
	Path   string
	Target string
	// FailOnMissing fails if file is already missing
	FailOnMissing bool `yaml:"fail_on_missing" config:"fail_on_missing"`
}

// Execute executes move file step.
func (r *MoveFileStep) Execute(rootDir string) error {
	path, isSubpath := joinPaths(rootDir, r.Path)
	if !isSubpath {
		return fmt.Errorf("invalid path value for operation 'Move': %s", path)
	}

	target, isSubpath := joinPaths(rootDir, r.Target)
	if !isSubpath {
		return fmt.Errorf("invalid target value for operation 'Move': %s", target)
	}

	err := os.Rename(path, target)

	if os.IsNotExist(err) && r.FailOnMissing {
		// is not found and should be reported
		return err
	}

	if err != nil && !os.IsNotExist(err) {
		// report others
		return err
	}

	return nil
}

// MoveFile creates a MoveFileStep
func MoveFile(path, target string, failOnMissing bool) *MoveFileStep {
	return &MoveFileStep{
		Path:          path,
		Target:        target,
		FailOnMissing: failOnMissing,
	}
}

// joinPaths joins paths and returns true if path is subpath of rootDir
func joinPaths(rootDir, path string) (string, bool) {
	if !filepath.IsAbs(path) {
		path = filepath.Join(rootDir, path)
	}

	absRoot := filepath.Clean(filepath.FromSlash(rootDir))
	absPath := filepath.Clean(filepath.FromSlash(path))

	// path on windows are case insensitive
	if runtime.GOOS == "windows" {
		absRoot = strings.ToLower(absRoot)
		absPath = strings.ToLower(absPath)
	}

	return absPath, strings.HasPrefix(absPath, absRoot)
}
