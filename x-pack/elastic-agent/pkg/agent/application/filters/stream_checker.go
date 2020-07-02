// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package filters

import (
	"strings"

	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/agent/errors"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/agent/transpiler"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/core/logger"
)

// ErrInvalidNamespace is error returned when namespace value provided is invalid.
var ErrInvalidNamespace = errors.New("provided namespace is invalid", errors.TypeConfig)

// ErrInvalidDataset is error returned when dataset name value provided is invalid.
var ErrInvalidDataset = errors.New("provided dataset name is invalid", errors.TypeConfig)

// StreamChecker checks for invalid values in stream namespace and dataset.
func StreamChecker(log *logger.Logger, ast *transpiler.AST) error {
	inputsNode, found := transpiler.Lookup(ast, "inputs")
	if !found {
		return nil
	}

	inputsNodeList, ok := inputsNode.Value().(*transpiler.List)
	if !ok {
		return nil
	}

	inputsNodeListCollection, ok := inputsNodeList.Value().([]transpiler.Node)
	if !ok {
		return errors.New("inputs is not a list", errors.TypeConfig)
	}

	for _, inputNode := range inputsNodeListCollection {
		// fail only if dataset.namespace or dataset[namespace] is found and invalid
		// not provided values are ok and will be fixed by rules
		if nsNode, found := inputNode.Find("dataset.namespace"); found {
			nsKey, ok := nsNode.(*transpiler.Key)
			if ok {
				if newNamespace := nsKey.Value().(transpiler.Node).String(); !isNamespaceValid(newNamespace) {
					return ErrInvalidNamespace
				}
			}
		} else {
			dsNode, found := inputNode.Find("dataset")
			if found {
				// got a dataset
				datasetMap, ok := dsNode.Value().(*transpiler.Dict)
				if ok {
					nsNode, found := datasetMap.Find("namespace")
					if found {
						nsKey, ok := nsNode.(*transpiler.Key)
						if ok {
							if newNamespace := nsKey.Value().(transpiler.Node).String(); !isNamespaceValid(newNamespace) {
								return ErrInvalidNamespace
							}
						}
					}
				}
			}
		}

		streamsNode, ok := inputNode.Find("streams")
		if !ok {
			continue
		}

		streamsList, ok := streamsNode.Value().(*transpiler.List)
		if !ok {
			continue
		}

		streamNodes, ok := streamsList.Value().([]transpiler.Node)
		if !ok {
			return errors.New("streams is not a list", errors.TypeConfig)
		}

		for _, streamNode := range streamNodes {
			streamMap, ok := streamNode.(*transpiler.Dict)
			if !ok {
				continue
			}

			// fix this only if in compact form
			if dsNameNode, found := streamMap.Find("dataset.name"); found {
				dsKey, ok := dsNameNode.(*transpiler.Key)
				if ok {
					if newDataset := dsKey.Value().(transpiler.Node).String(); !isDatasetValid(newDataset) {
						return ErrInvalidDataset
					}
				}
			} else {
				datasetNode, found := streamMap.Find("dataset")
				if found {
					datasetMap, ok := datasetNode.Value().(*transpiler.Dict)
					if !ok {
						continue
					}

					dsNameNode, found := datasetMap.Find("name")
					if found {
						dsKey, ok := dsNameNode.(*transpiler.Key)
						if ok {
							if newDataset := dsKey.Value().(transpiler.Node).String(); !isDatasetValid(newDataset) {
								return ErrInvalidDataset
							}
						}
					}
				}
			}
		}
	}

	return nil
}

// The only two requirement are that it has only characters allowed in an Elasticsearch index name
// and does NOT contain a `-`.
// Index names must meet the following criteria:
//     Lowercase only
//     Cannot include \, /, *, ?, ", <, >, |, ` ` (space character), ,, #
//     Cannot start with -, _, +
//     Cannot be . or ..

func isNamespaceValid(namespace string) bool {
	// Cannot be . or ..
	if namespace == "." || namespace == ".." {
		return false
	}

	if len(namespace) <= 0 || len(namespace) > 255 {
		return false
	}

	// Lowercase only
	if strings.ToLower(namespace) != namespace {
		return false
	}

	// Cannot include \, /, *, ?, ", <, >, |, ` ` (space character), ,, #
	if strings.ContainsAny(namespace, "\\/*?\"<>| ,#-") {
		return false
	}

	// Cannot start with -, _, +
	if strings.HasPrefix(namespace, "-") || strings.HasPrefix(namespace, "_") || strings.HasPrefix(namespace, "+") {
		return false
	}

	return true
}

// The same requirements as for the namespace apply.
func isDatasetValid(dataset string) bool {
	// Cannot be . or ..
	if dataset == "." || dataset == ".." {
		return false
	}

	if len(dataset) <= 0 || len(dataset) > 255 {
		return false
	}

	// Lowercase only
	if strings.ToLower(dataset) != dataset {
		return false
	}

	// Cannot include \, /, *, ?, ", <, >, |, ` ` (space character), ,, #
	if strings.ContainsAny(dataset, "\\/*?\"<>| ,#-") {
		return false
	}

	// Cannot start with -, _, +
	if strings.HasPrefix(dataset, "-") || strings.HasPrefix(dataset, "_") || strings.HasPrefix(dataset, "+") {
		return false
	}

	return true
}
