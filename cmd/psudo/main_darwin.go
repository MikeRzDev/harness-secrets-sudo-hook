//go:build darwin && psudo_testapp

package main

import "runtime"

// AppKit must run on the main thread: psudo.app draws its dialogs from the
// main goroutine, which this keeps on the main thread.
func init() { runtime.LockOSThread() }
