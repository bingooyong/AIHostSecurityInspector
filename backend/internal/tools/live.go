package tools

import "os"

// LiveToolsEnv is the explicit opt-in for real vendor-binary adapter tests.
// Default make check / CI must leave this unset so host tools are never used
// to audit the runner or leak host identity into public logs.
const LiveToolsEnv = "HOSTSEC_LIVE_TOOLS"

func LiveToolsEnabled() bool {
	return os.Getenv(LiveToolsEnv) == "1"
}
