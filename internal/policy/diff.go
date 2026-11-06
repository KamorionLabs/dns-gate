package policy

import (
	"encoding/json"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/KamorionLabs/dns-gate/internal/uiapi"
)

// DocumentYAML renders a managed document as YAML with the JSON field
// names, keys sorted (stable output for diffs and exports).
func DocumentYAML(d uiapi.PolicyDocument) (string, error) {
	Normalize(&d)
	b, err := json.Marshal(d)
	if err != nil {
		return "", err
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return "", err
	}
	out, err := yaml.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// UnifiedDiff returns a unified diff (3 lines of context) between two texts.
func UnifiedDiff(a, b, nameA, nameB string) string {
	al, bl := splitLines(a), splitLines(b)
	ops := lcsDiff(al, bl)
	if len(ops) == 0 {
		return ""
	}
	changed := false
	for _, o := range ops {
		if o.kind != ' ' {
			changed = true
			break
		}
	}
	if !changed {
		return ""
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "--- %s\n+++ %s\n", nameA, nameB)
	const ctx = 3
	i := 0
	for i < len(ops) {
		if ops[i].kind == ' ' {
			i++
			continue
		}
		start := i - ctx
		if start < 0 {
			start = 0
		}
		end := i
		for end < len(ops) {
			if ops[end].kind != ' ' {
				end++
				continue
			}
			run := end
			for run < len(ops) && ops[run].kind == ' ' {
				run++
			}
			if run-end > 2*ctx || run == len(ops) {
				end += min(ctx, run-end)
				break
			}
			end = run
		}
		aStart, bStart, aCount, bCount := ops[start].a, ops[start].b, 0, 0
		for _, o := range ops[start:end] {
			if o.kind != '+' {
				aCount++
			}
			if o.kind != '-' {
				bCount++
			}
		}
		fmt.Fprintf(&sb, "@@ -%d,%d +%d,%d @@\n", aStart+1, aCount, bStart+1, bCount)
		for _, o := range ops[start:end] {
			sb.WriteByte(o.kind)
			sb.WriteString(o.text)
			sb.WriteByte('\n')
		}
		i = end
	}
	return sb.String()
}

type diffOp struct {
	kind byte // ' ', '-', '+'
	text string
	a, b int // line index in a and b at this op
}

func splitLines(s string) []string {
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// lcsDiff is a longest-common-subsequence line diff, fine for policy
// documents (a few thousand lines at most).
func lcsDiff(a, b []string) []diffOp {
	n, m := len(a), len(b)
	dp := make([][]int, n+1)
	for i := range dp {
		dp[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				dp[i][j] = dp[i+1][j+1] + 1
			} else {
				dp[i][j] = max(dp[i+1][j], dp[i][j+1])
			}
		}
	}
	var ops []diffOp
	i, j := 0, 0
	for i < n || j < m {
		switch {
		case i < n && j < m && a[i] == b[j]:
			ops = append(ops, diffOp{' ', a[i], i, j})
			i++
			j++
		case j < m && (i == n || dp[i][j+1] >= dp[i+1][j]):
			ops = append(ops, diffOp{'+', b[j], i, j})
			j++
		default:
			ops = append(ops, diffOp{'-', a[i], i, j})
			i++
		}
	}
	return ops
}
