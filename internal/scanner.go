package internal

import (
	"fmt"
	"regexp"

	"github.com/BurntSushi/toml"
)

// --- rule loading -----------------------------------------------------

type ruleConfig struct {
	Rules []rule `toml:"rules"`
}

type rule struct {
	ID          string   `toml:"id"`
	Description string   `toml:"description"`
	Regex       string   `toml:"regex"`
	Tags        []string `toml:"tags"`
}

type CompiledRule struct {
	ID          string
	Description string
	Regex       *regexp.Regexp
	Tags        []string
}

// LoadRules reads a gitleaks-style TOML rule file (see templates/js-secrets.toml)
// and compiles every rule's regex. Rules with no `tags` field default to
// tags = ["secret"].
func LoadRules(path string) ([]CompiledRule, error) {
	var cfg ruleConfig
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return nil, fmt.Errorf("loading rules from %s: %w", path, err)
	}

	var compiled []CompiledRule
	for _, r := range cfg.Rules {
		re, err := regexp.Compile(r.Regex)
		if err != nil {
			fmt.Printf("skipping invalid regex for rule %s: %v\n", r.ID, err)
			continue
		}

		tags := r.Tags
		if len(tags) == 0 {
			tags = []string{"secret"}
		}

		compiled = append(compiled, CompiledRule{
			ID:          r.ID,
			Description: r.Description,
			Regex:       re,
			Tags:        tags,
		})
	}
	return compiled, nil
}

// --- scanning -----------------------------------------------------------

type Finding struct {
	RuleID      string
	Description string
	Tags        []string
	Match       string
	Source      string
}

// Scan runs every rule against content in a single pass. If a rule's
// regex has a capture group, the first captured group is used as the
// match; otherwise the full match is used.
func Scan(content, source string, rules []CompiledRule) []Finding {
	var findings []Finding

	for _, r := range rules {
		groups := r.Regex.FindAllStringSubmatch(content, -1)
		for _, g := range groups {
			match := g[0]
			if len(g) > 1 && g[1] != "" {
				match = g[1]
			}
			findings = append(findings, Finding{
				RuleID:      r.ID,
				Description: r.Description,
				Tags:        r.Tags,
				Match:       match,
				Source:      source,
			})
		}
	}
	return findings
}

// --- filtering ------------------------------------------------------

func HasTag(f Finding, tag string) bool {
	for _, t := range f.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

func FilterByTag(findings []Finding, tag string) []Finding {
	var out []Finding
	for _, f := range findings {
		if HasTag(f, tag) {
			out = append(out, f)
		}
	}
	return out
}

// Dedupe collapses findings with the same (RuleID, Match) pair, keeping
// the first source seen.
func Dedupe(findings []Finding) []Finding {
	seen := make(map[string]bool)
	var out []Finding
	for _, f := range findings {
		key := f.RuleID + "|" + f.Match
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}
