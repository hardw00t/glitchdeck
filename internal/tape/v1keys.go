package tape

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

func v1Keys(doc *yaml.Node) error {
	has := func(node *yaml.Node, keys ...string) bool {
		for _, k := range keys {
			if yamlField(node, k) != nil {
				return true
			}
		}
		return false
	}
	root := doc.Content[0]
	if has(root, "tls_mitm", "upstream_allow", "tls_passthrough", "expect") {
		return fmt.Errorf("new keys require version: 2")
	}
	ruleSets := []*yaml.Node{yamlField(root, "rules")}
	for _, c := range yamlItems(yamlField(root, "config_changes")) {
		ruleSets = append(ruleSets, yamlField(c, "rules"))
	}
	for _, rules := range ruleSets {
		for _, r := range yamlItems(rules) {
			if has(yamlField(r, "match"), "host", "scheme", "proto") {
				return fmt.Errorf("new rule keys require version: 2")
			}
		}
	}
	for _, s := range yamlItems(yamlField(root, "script")) {
		if has(s, "stream", "grpc") || has(yamlField(s, "http"), "url", "proto") {
			return fmt.Errorf("new step keys require version: 2")
		}
	}
	for _, a := range yamlItems(yamlField(root, "assertions")) {
		if has(a, "stream_step", "grpc_step", "expect_sse", "expect_grpc_status") {
			return fmt.Errorf("new assertion keys require version: 2")
		}
	}
	return nil
}

func integerFaultBounds(doc *yaml.Node) error {
	expect := yamlField(doc.Content[0], "expect")
	for _, fault := range yamlItems(yamlField(expect, "faults")) {
		for _, name := range [...]string{"min_applied", "max_applied"} {
			if value := yamlField(fault, name); value != nil {
				if value.Kind == yaml.AliasNode {
					value = value.Alias
				}
				if value.Kind != yaml.ScalarNode || value.ShortTag() != "!!int" {
					return fmt.Errorf("expect.faults %s must be a nonnegative integer", name)
				}
			}
		}
	}
	return nil
}

func yamlItems(n *yaml.Node) []*yaml.Node {
	if n != nil && n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	if n == nil || n.Kind != yaml.SequenceNode {
		return nil
	}
	return n.Content
}

func yamlField(n *yaml.Node, key string) *yaml.Node {
	if n != nil && n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if k.Kind == yaml.AliasNode {
			k = k.Alias
		}
		if k.Value == key {
			return v
		}
	}
	for i := 0; i < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if k.Tag == "!!merge" {
			if found := yamlField(v, key); found != nil {
				return found
			}
			for _, m := range yamlItems(v) {
				if found := yamlField(m, key); found != nil {
					return found
				}
			}
		}
	}
	return nil
}
