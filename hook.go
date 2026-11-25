package main

import (
	"encoding/json"
	"io"
)

// hookIn is the part of a PreToolUse payload the hooks read.
type hookIn struct {
	SessionID string `json:"session_id"`
	// AgentID is set only inside a subagent; the main thread leaves it empty.
	AgentID   string `json:"agent_id"`
	ToolName  string `json:"tool_name"`
	Cwd       string `json:"cwd"`
	ToolInput struct {
		Path         string `json:"path"`
		Pattern      string `json:"pattern"`
		Glob         string `json:"glob"`
		Command      string `json:"command"`
		FilePath     string `json:"file_path"`
		NotebookPath string `json:"notebook_path"`
	} `json:"tool_input"`
}

// shellCommand returns the command line of a tool call that runs one. Monitor
// starts shell commands too, and a Bash-matched hook sees them.
func (in hookIn) shellCommand() (string, bool) {
	switch in.ToolName {
	case "Bash", "Monitor":
		return in.ToolInput.Command, in.ToolInput.Command != ""
	}
	return "", false
}

// emit writes a PreToolUse permission decision.
func emit(w io.Writer, decision, reason string) {
	json.NewEncoder(w).Encode(map[string]any{
		"hookSpecificOutput": map[string]string{
			"hookEventName":            "PreToolUse",
			"permissionDecision":       decision,
			"permissionDecisionReason": reason,
		},
	})
}
