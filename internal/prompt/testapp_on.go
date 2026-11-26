//go:build psudo_testapp

package prompt

// TestApp is true in a test build (go build -tags psudo_testapp, make
// install-test-app): only such a build can show its dialogs through
// /Applications/psudo.app, so computer use can answer them in a regression
// run. A normal build has no app backend, no --dialog mode and no AppKit code,
// so a psudo.app that someone puts in place is never asked anything.
const TestApp = true
