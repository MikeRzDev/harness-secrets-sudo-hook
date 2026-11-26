//go:build !darwin || !cgo || !psudo_testapp

package prompt

// render has no AppKit here: the dialog is shown by another backend.
func render(Dialog) Result { return Result{Outcome: Unavailable} }
