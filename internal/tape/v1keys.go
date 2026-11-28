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

func checkYAMLGraph(root *yaml.Node) error {
	type visit struct {
		node *yaml.Node
		exit bool
	}
	stack := []visit{{node: root}}
	state := make(map[*yaml.Node]uint8)
	aliases := 0
	for len(stack) != 0 {
		item := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		n := item.node
		if n == nil {
			continue
		}
		if item.exit {
			state[n] = 2
			continue
		}
		if state[n] == 1 {
			return fmt.Errorf("cyclic YAML alias")
		}
		if state[n] == 2 {
			continue
		}
		state[n] = 1
		stack = append(stack, visit{node: n, exit: true})
		if n.Kind == yaml.AliasNode || n.Tag == "!!merge" {
			aliases++
			if aliases > 100000 {
				return fmt.Errorf("too many YAML aliases or merges")
			}
		}
		if n.Kind == yaml.AliasNode {
			stack = append(stack, visit{node: n.Alias})
		}
		for i := len(n.Content) - 1; i >= 0; i-- {
			stack = append(stack, visit{node: n.Content[i]})
		}
	}
	return nil
}

func yamlField(n *yaml.Node, key string) *yaml.Node {
	seen := make(map[*yaml.Node]bool)
	stack := []*yaml.Node{n}
	for len(stack) != 0 {
		n = stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if n == nil || seen[n] {
			continue
		}
		seen[n] = true
		if n.Kind == yaml.AliasNode {
			stack = append(stack, n.Alias)
			continue
		}
		if n.Kind == yaml.SequenceNode {
			for i := len(n.Content) - 1; i >= 0; i-- {
				stack = append(stack, n.Content[i])
			}
			continue
		}
		if n.Kind != yaml.MappingNode {
			continue
		}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind == yaml.AliasNode {
				k = k.Alias
			}
			if k != nil && k.Value == key {
				return n.Content[i+1]
			}
		}
		for i := len(n.Content) - 2; i >= 0; i -= 2 {
			if n.Content[i].Tag == "!!merge" {
				stack = append(stack, n.Content[i+1])
			}
		}
	}
	return nil
}
