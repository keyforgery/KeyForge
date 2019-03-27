package liger

/*
#cgo LDFLAGS: -L/usr/local/lib/ -lrelic
#include <relic/relic.h>

*/
import "C"

// Setup must be called before any other operations are called.
// Initializes the curve parameters in RELIC
func PrintParams() {
	C.ep_param_print()
}
