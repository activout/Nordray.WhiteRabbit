// Package skill holds the agent skill that describes rabbit, embedded so `rabbit skill install` matches the binary.
package skill

import _ "embed"

//go:embed SKILL.md
var Markdown []byte
