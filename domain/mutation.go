package domain

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/MagalixTechnologies/core/logger"
	"sigs.k8s.io/kustomize/kyaml/yaml"
)

var (
	regex = regexp.MustCompile("^([a-zA-Z0-9]+)\\[([0-9]+)\\]")
)

const (
	mutatedLabel = "pac.weave.works/mutated"
)

type MutationResult struct {
	raw  []byte
	node *yaml.RNode
}

func NewMutationResult(entity Entity) (*MutationResult, error) {
	raw, err := json.Marshal(entity.Manifest)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal entity. error: %w", err)
	}

	var ynode yaml.Node
	err = yaml.Unmarshal(raw, &ynode)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal entity. error: %w", err)
	}

	return &MutationResult{
		raw:  raw,
		node: yaml.NewRNode(&ynode),
	}, nil
}

func (m *MutationResult) Mutate(occurrences []Occurrence) ([]Occurrence, error) {
	var mutated bool
	for i, occurrence := range occurrences {
		if occurrence.ViolatingKey == nil || occurrence.RecommendedValue == nil {
			continue
		}

		path := parseKeyPath(*occurrence.ViolatingKey)
		pathGetter := yaml.LookupCreate(yaml.MappingNode, path...)
		node, err := m.node.Pipe(pathGetter)
		if err != nil {
			logger.Errorw("failed to mutate")
			continue
		}

		if node == nil {
			logger.Errorw("field not found")
			continue
		}

		value := occurrence.RecommendedValue
		if number, ok := value.(json.Number); ok {
			value, _ = number.Float64()
		}

		err = node.Document().Encode(value)
		if err != nil {
			logger.Errorw("failed to mutate")
			continue
		}

		occurrences[i].Mutated = true
		mutated = true
	}
	if mutated {
		labels := m.node.GetLabels()
		labels[mutatedLabel] = ""
		m.node.SetLabels(labels)
	}
	return occurrences, nil
}

func (m *MutationResult) Old() []byte {
	return m.raw
}

func (m *MutationResult) Mutated() ([]byte, error) {
	return m.node.MarshalJSON()
}

func parseKeyPath(path string) []string {
	var keys []string
	parts := strings.Split(path, ".")
	for _, part := range parts {
		groups := regex.FindStringSubmatch(part)
		if groups == nil {
			keys = append(keys, part)
		} else {
			keys = append(keys, groups[1:]...)
		}
	}
	return keys
}
