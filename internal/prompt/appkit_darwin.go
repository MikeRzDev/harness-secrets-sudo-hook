//go:build darwin && cgo && psudo_testapp

package prompt

/*
#cgo CFLAGS: -x objective-c -fobjc-arc -Wno-deprecated-declarations
#cgo LDFLAGS: -framework AppKit
#include <stdlib.h>
#include <string.h>
#import <AppKit/AppKit.h>

// outcome: 0 answered, 1 refused, 2 timed out, 3 unavailable.
typedef struct {
	int outcome;
	int button;
	char *answer;
} psudo_result;

// PsudoDialog draws one Dialog exactly as given: buttons in order, the
// default and cancel buttons it names, a hidden field when asked. It decides
// nothing; the rules live in the Go Dialog.
@interface PsudoDialog : NSObject <NSApplicationDelegate> {
@public
	psudo_result result;
}
@property(copy) NSString *title;
@property(copy) NSString *text;
@property BOOL ask;
@property BOOL hidden;
@property(copy) NSArray<NSString *> *buttons;
@property NSInteger defaultButton;
@property NSInteger cancelButton;
@property NSInteger seconds;
@property BOOL gaveUp;
@end

@implementation PsudoDialog
- (void)giveUp:(NSTimer *)timer {
	self.gaveUp = YES;
	[NSApp abortModal];
}

- (void)comeForward:(NSTimer *)timer {
	[NSApp activateIgnoringOtherApps:YES];
	[(NSWindow *)timer.userInfo makeKeyAndOrderFront:nil];
}

// The dialog is drawn once the app has finished launching: only then can it
// become the active app and take the keyboard, for a person and for computer
// use alike.
- (void)applicationDidFinishLaunching:(NSNotification *)note {
	[NSApp activateIgnoringOtherApps:YES];
	[[NSRunningApplication currentApplication] activateWithOptions:NSApplicationActivateAllWindows];

	NSAlert *alert = [[NSAlert alloc] init];
	alert.messageText = self.title;
	alert.informativeText = self.text; // plain text: shown verbatim, never markup
	alert.icon = [NSImage imageNamed:NSImageNameCaution];

	// NSAlert puts the first button it gets on the right. They are added right
	// to left, so they read left to right in the Dialog's order. Every key
	// equivalent is cleared, then Return and Escape go to the buttons the
	// Dialog names, and to no other.
	NSInteger n = (NSInteger)self.buttons.count;
	NSMutableArray<NSButton *> *byIndex = [NSMutableArray arrayWithCapacity:(NSUInteger)n];
	for (NSInteger i = 0; i < n; i++) {
		[byIndex addObject:(NSButton *)[NSNull null]];
	}
	for (NSInteger i = n - 1; i >= 0; i--) {
		NSButton *b = [alert addButtonWithTitle:self.buttons[(NSUInteger)i]];
		b.keyEquivalent = @"";
		byIndex[(NSUInteger)i] = b;
	}
	byIndex[(NSUInteger)self.defaultButton].keyEquivalent = @"\r";
	if (self.cancelButton >= 0) {
		byIndex[(NSUInteger)self.cancelButton].keyEquivalent = @"\033";
	}

	NSTextField *field = nil;
	if (self.ask) {
		NSRect frame = NSMakeRect(0, 0, 280, 24);
		field = self.hidden ? [[NSSecureTextField alloc] initWithFrame:frame] : [[NSTextField alloc] initWithFrame:frame];
		alert.accessoryView = field;
		alert.window.initialFirstResponder = field;
	}
	alert.window.level = NSFloatingWindowLevel;
	[alert layout];
	[alert.window center];
	[alert.window makeKeyAndOrderFront:nil];

	NSTimer *timer = [NSTimer timerWithTimeInterval:(NSTimeInterval)self.seconds target:self
		selector:@selector(giveUp:) userInfo:nil repeats:NO];
	[[NSRunLoop currentRunLoop] addTimer:timer forMode:NSModalPanelRunLoopMode];
	// macOS may not let a just-launched app take the front at once: ask again
	// once the dialog is on screen.
	NSTimer *front = [NSTimer timerWithTimeInterval:0.15 target:self selector:@selector(comeForward:)
		userInfo:alert.window repeats:NO];
	[[NSRunLoop currentRunLoop] addTimer:front forMode:NSModalPanelRunLoopMode];
	NSModalResponse response = [alert runModal];
	[timer invalidate];

	result.outcome = 1;
	result.button = 0;
	result.answer = NULL;
	if (self.gaveUp) {
		result.outcome = 2;
	} else {
		// The first button added (the rightmost) is NSAlertFirstButtonReturn.
		NSInteger index = n - 1 - (NSInteger)(response - NSAlertFirstButtonReturn);
		if (index >= 0 && index < n && index != self.cancelButton) {
			result.outcome = 0;
			result.button = (int)index;
			if (field != nil) {
				const char *s = field.stringValue.UTF8String;
				result.answer = strdup(s != NULL ? s : "");
			}
		}
	}
	[NSApp stop:nil];
	// stop: takes effect after the next event, so one is posted.
	NSEvent *wake = [NSEvent otherEventWithType:NSEventTypeApplicationDefined location:NSZeroPoint
		modifierFlags:0 timestamp:0 windowNumber:0 context:nil subtype:0 data1:0 data2:0];
	[NSApp postEvent:wake atStart:YES];
}
@end

static NSString *psudo_string(const char *s) {
	NSString *v = s != NULL ? [NSString stringWithUTF8String:s] : nil;
	return v != nil ? v : @"";
}

// psudo_show must run on the main thread (psudo locks it in an init).
static psudo_result psudo_show(const char *title, const char *text, int ask, int hidden,
		const char **buttons, int n, int def, int cancel, int seconds) {
	psudo_result unavailable = {3, 0, NULL};
	@autoreleasepool {
		NSApplication *app = [NSApplication sharedApplication];
		if (app == nil) {
			return unavailable;
		}
		PsudoDialog *d = [[PsudoDialog alloc] init];
		d->result = unavailable;
		d.title = psudo_string(title);
		d.text = psudo_string(text);
		d.ask = ask != 0;
		d.hidden = hidden != 0;
		NSMutableArray<NSString *> *labels = [NSMutableArray arrayWithCapacity:(NSUInteger)n];
		for (int i = 0; i < n; i++) {
			[labels addObject:psudo_string(buttons[i])];
		}
		d.buttons = labels;
		d.defaultButton = def;
		d.cancelButton = cancel;
		d.seconds = seconds;
		// A regular app (with a Dock icon while it runs): an accessory app is
		// not one that computer use can be given.
		[app setActivationPolicy:NSApplicationActivationPolicyRegular];
		app.delegate = d;
		[app run];
		return d->result;
	}
}

static void psudo_free_answer(char *s) {
	if (s != NULL) {
		memset(s, 0, strlen(s));
		free(s);
	}
}
*/
import "C"

import "unsafe"

// render draws d with AppKit and reports how it ended.
func render(d Dialog) Result {
	title, text := C.CString(d.Title), C.CString(d.Text)
	defer C.free(unsafe.Pointer(title))
	defer C.free(unsafe.Pointer(text))
	labels := make([]*C.char, len(d.Buttons))
	for i, b := range d.Buttons {
		labels[i] = C.CString(b)
		defer C.free(unsafe.Pointer(labels[i]))
	}
	cbuttons := (**C.char)(C.malloc(C.size_t(len(labels)) * C.size_t(unsafe.Sizeof(labels[0]))))
	defer C.free(unsafe.Pointer(cbuttons))
	copy(unsafe.Slice(cbuttons, len(labels)), labels)

	b2i := func(b bool) C.int {
		if b {
			return 1
		}
		return 0
	}
	r := C.psudo_show(title, text, b2i(d.Kind == KindAsk), b2i(d.Hidden), cbuttons, C.int(len(labels)),
		C.int(d.Default), C.int(d.Cancel), C.int(d.Seconds))
	res := Result{Button: int(r.button)}
	switch r.outcome {
	case 0:
		res.Outcome = Answered
	case 1:
		res.Outcome = Refused
	case 2:
		res.Outcome = TimedOut
	default:
		res.Outcome = Unavailable
	}
	if r.answer != nil {
		res.Answer = C.GoString(r.answer)
		C.psudo_free_answer(r.answer)
	}
	return res
}
