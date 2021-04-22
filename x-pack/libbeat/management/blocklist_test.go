// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package management

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/elastic/beats/v7/libbeat/common"
	"github.com/elastic/beats/v7/x-pack/libbeat/management/api"
)

func TestConfigBlocklistSettingsUnpack(t *testing.T) {
	tests := []struct {
		name     string
		config   *common.Config
		error    bool
		expected ConfigBlocklistSettings
	}{
		{
			name: "Simple config",
			config: common.MustNewConfigFrom(map[string]interface{}{
				"foo": "bar",
			}),
			expected: ConfigBlocklistSettings{
				Patterns: map[string]string{
					"foo": "bar",
				},
			},
		},
		{
			name:   "Wrong config",
			config: common.MustNewConfigFrom([]string{"a", "b"}),
			error:  true,
		},
		{
			name: "Tree config",
			config: common.MustNewConfigFrom(map[string]interface{}{
				"foo": map[string]interface{}{
					"bar": "baz",
				},
			}),
			expected: ConfigBlocklistSettings{
				Patterns: map[string]string{
					"foo.bar": "baz",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var result ConfigBlocklistSettings
			err := test.config.Unpack(&result)
			if test.error {
				assert.Error(t, err)
			}
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestConfigBlocklist(t *testing.T) {
	tests := []struct {
		name     string
		patterns map[string]string
		blocks   api.ConfigBlocks
		blocked  bool
	}{
		{
			name:    "No patterns",
			blocked: false,
			blocks: api.ConfigBlocks{
				api.ConfigBlocksWithType{
					Type: "output",
					Blocks: []*api.ConfigBlock{
						{
							Raw: map[string]interface{}{
								"output": "console",
							},
						},
					},
				},
			},
		},
		{
			name:    "Blocklisted dict key",
			blocked: true,
			patterns: map[string]string{
				"output": "^console$",
			},
			blocks: api.ConfigBlocks{
				api.ConfigBlocksWithType{
					Type: "output",
					Blocks: []*api.ConfigBlock{
						{
							Raw: map[string]interface{}{
								"console": map[string]interface{}{
									"pretty": "true",
								},
							},
						},
						{
							Raw: map[string]interface{}{
								"elasticsearch": map[string]interface{}{
									"host": "localhost",
								},
							},
						},
					},
				},
			},
		},
		{
			name:    "Blocklisted value key",
			blocked: true,
			patterns: map[string]string{
				"metricbeat.modules.module": "k.{8}s",
			},
			blocks: api.ConfigBlocks{
				api.ConfigBlocksWithType{
					Type: "metricbeat.modules",
					Blocks: []*api.ConfigBlock{
						{
							Raw: map[string]interface{}{
								"module": "kubernetes",
								"hosts":  "localhost:10255",
							},
						},
					},
				},
			},
		},
		{
			name:    "Blocklisted value in a list",
			blocked: true,
			patterns: map[string]string{
				"metricbeat.modules.metricsets": "event",
			},
			blocks: api.ConfigBlocks{
				api.ConfigBlocksWithType{
					Type: "metricbeat.modules",
					Blocks: []*api.ConfigBlock{
						{
							Raw: map[string]interface{}{
								"module": "kubernetes",
								"metricsets": []string{
									"event",
									"default",
								},
							},
						},
						{
							Raw: map[string]interface{}{
								"module": "kubernetes",
								"metricsets": []string{
									"default",
								},
							},
						},
					},
				},
			},
		},
		{
			name:    "Blocklisted value in a deep list",
			blocked: true,
			patterns: map[string]string{
				"filebeat.inputs.containers.ids": "1ffeb0dbd13",
			},
			blocks: api.ConfigBlocks{
				api.ConfigBlocksWithType{
					Type: "metricbeat.modules",
					Blocks: []*api.ConfigBlock{
						{
							Raw: map[string]interface{}{
								"module": "kubernetes",
								"metricsets": []string{
									"event",
									"default",
								},
							},
						},
					},
				},
				api.ConfigBlocksWithType{
					Type: "filebeat.inputs",
					Blocks: []*api.ConfigBlock{
						{
							Raw: map[string]interface{}{
								"type": "docker",
								"containers": map[string]interface{}{
									"ids": []string{
										"1ffeb0dbd13",
									},
								},
							},
						},
						{
							Raw: map[string]interface{}{
								"type": "docker",
								"containers": map[string]interface{}{
									"ids": []string{
										"256425931c2",
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name:    "Blocklisted dict key in a list",
			blocked: true,
			patterns: map[string]string{
				"list.of.elements":            "forbidden",
				"list.of.elements.disallowed": "yes",
			},
			blocks: api.ConfigBlocks{
				api.ConfigBlocksWithType{
					Type: "list",
					Blocks: []*api.ConfigBlock{
						{
							Raw: map[string]interface{}{
								"of": map[string]interface{}{
									"elements": []interface{}{
										map[string]interface{}{
											"forbidden": "yes",
										},
									},
								},
							},
						},
						{
							Raw: map[string]interface{}{
								"of": map[string]interface{}{
									"elements": []interface{}{
										map[string]interface{}{
											"allowed": "yes",
										},
									},
								},
							},
						},
						{
							Raw: map[string]interface{}{
								"of": map[string]interface{}{
									"elements": []interface{}{
										map[string]interface{}{
											"disallowed": "yes",
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := ConfigBlocklistSettings{
				Patterns: test.patterns,
			}
			bl, err := NewConfigBlocklist(cfg)
			if err != nil {
				t.Fatal(err)
			}

			errs := bl.Detect(test.blocks)
			assert.Equal(t, test.blocked, !errs.IsEmpty())
		})
	}
}