// Package yamlenv decodes YAML config files with ${VAR} references in values
// expanded from the environment, so secrets can be injected in CI.
package yamlenv

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Decode reads path into out. Unknown fields are rejected; a referenced but
// undefined environment variable is an error. Comments are not expanded.
func Decode(path string, out any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var root yaml.Node
	if err := yaml.Unmarshal(raw, &root); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	var missing []string
	expandNode(&root, &missing)
	if len(missing) > 0 {
		return fmt.Errorf("%s: undefined environment variables: %s", path, strings.Join(missing, ", "))
	}
	expanded, err := yaml.Marshal(&root)
	if err != nil {
		return err
	}
	dec := yaml.NewDecoder(bytes.NewReader(expanded))
	dec.KnownFields(true)
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func expandNode(n *yaml.Node, missing *[]string) {
	if n.Kind == yaml.ScalarNode && strings.Contains(n.Value, "${") {
		n.Value = os.Expand(n.Value, func(k string) string {
			v, ok := os.LookupEnv(k)
			if !ok {
				*missing = append(*missing, k)
			}
			return v
		})
		n.Style = yaml.DoubleQuotedStyle
	}
	for _, c := range n.Content {
		expandNode(c, missing)
	}
}

// Duration is a time.Duration that unmarshals from strings like "30s".
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	v, err := time.ParseDuration(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	d.Duration = v
	return nil
}

func (d Duration) MarshalYAML() (any, error) { return d.String(), nil }
