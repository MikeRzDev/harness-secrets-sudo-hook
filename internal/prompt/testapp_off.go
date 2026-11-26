//go:build !psudo_testapp

package prompt

// TestApp is false in a normal build: on macOS every dialog comes from
// osascript, which no agent can operate. See testapp_on.go.
const TestApp = false
