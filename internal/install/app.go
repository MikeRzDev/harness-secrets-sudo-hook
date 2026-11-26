package install

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// AppName is the test app psudo can install on macOS. Its copy of psudo
// draws psudo's dialogs as an app of its own, which tools that work with apps
// (computer use) can be given, so a regression run can answer them; an
// osascript dialog belongs to no app. It is for tests only: the harness
// installs do not create it, and without it psudo's dialogs come from
// osascript, which no agent can operate.
const AppName = "psudo.app"

// AppBundleID identifies psudo.app.
const AppBundleID = "io.github.mikerzdev.psudo"

const lsregister = "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"

// infoPlist describes psudo.app. There is no LSUIElement: while a dialog is
// open the app has a Dock icon, because an app without one is not one that
// computer use can be given, and it could not take the keyboard either.
const infoPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleIdentifier</key><string>` + AppBundleID + `</string>
	<key>CFBundleName</key><string>psudo</string>
	<key>CFBundleDisplayName</key><string>psudo</string>
	<key>CFBundleExecutable</key><string>psudo</string>
	<key>CFBundlePackageType</key><string>APPL</string>
	<key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
	<key>LSMinimumSystemVersion</key><string>11.0</string>
	<key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
`

// app is where psudo.app goes, or "" when there is none to install.
func (in *Installer) app() string {
	if in.GOOS != "darwin" || in.AppDir == "" {
		return ""
	}
	return filepath.Join(in.AppDir, AppName)
}

// InstallTestApp puts psudo.app in AppDir with a copy of this psudo, signs it
// ad hoc and registers it with Launch Services. psudo uses it only while its
// binary is the same as the psudo that shows the dialog (internal/prompt), so
// install it from the same build as the harness copy.
func (in *Installer) InstallTestApp() error {
	app := in.app()
	if app == "" {
		return errors.New("the test app is for macOS only")
	}
	if err := in.writeApp(app); err != nil {
		return fmt.Errorf("could not install %s: %w", app, err)
	}
	in.say("Installed %s for tests: psudo's dialogs come from it until psudo --uninstall=test-app", app)
	return nil
}

// UninstallTestApp removes psudo.app: psudo's dialogs come from osascript again.
func (in *Installer) UninstallTestApp() error {
	app := in.app()
	if app == "" {
		return nil
	}
	in.deleteApp(app)
	return nil
}

func (in *Installer) writeApp(app string) error {
	contents := filepath.Join(app, "Contents")
	macos := filepath.Join(contents, "MacOS")
	if err := os.MkdirAll(macos, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(contents, "Info.plist"), []byte(infoPlist), 0o644); err != nil {
		return err
	}
	if err := copyBinary(in.Exe, filepath.Join(macos, "psudo")); err != nil {
		return err
	}
	if in.Exec == nil {
		return nil
	}
	// Signed after the copy: changing the binary would void the signature.
	if r, err := in.Exec("/usr/bin/codesign", []string{"--force", "--sign", "-", app}, nil); err != nil || r.Code != 0 {
		return fmt.Errorf("codesign: %v %s", err, r.Stderr)
	}
	if r, err := in.Exec(lsregister, []string{"-f", app}, nil); err != nil || r.Code != 0 {
		return fmt.Errorf("lsregister: %v %s", err, r.Stderr)
	}
	return nil
}

// removeApp deletes a test psudo.app once no harness has psudo installed any more.
func (in *Installer) removeApp() {
	app := in.app()
	if app == "" {
		return
	}
	if _, err := os.Stat(filepath.Join(in.ClaudeDir(), "psudo")); err == nil {
		return
	}
	if dir, err := in.CodexDir(); err == nil {
		if _, err := os.Stat(filepath.Join(dir, "psudo")); err == nil {
			return
		}
	}
	in.deleteApp(app)
}

// deleteApp removes app if it is one psudo made.
func (in *Installer) deleteApp(app string) {
	data, err := os.ReadFile(filepath.Join(app, "Contents", "Info.plist"))
	if err != nil || !strings.Contains(string(data), "<string>"+AppBundleID+"</string>") {
		return // not one psudo made
	}
	if in.Exec != nil {
		in.Exec(lsregister, []string{"-u", app}, nil)
	}
	if err := os.RemoveAll(app); err == nil {
		in.say("Removed %s", app)
	}
}
