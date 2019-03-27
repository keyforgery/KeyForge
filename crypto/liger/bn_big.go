package liger

/*
#cgo LDFLAGS: -L/usr/local/lib/ -lrelic
#include <relic/relic.h>

extern int setup();

bn_t newBN() {
	setup();
	bn_t b;
	bn_null(b);
	bn_new(b);
	bn_zero(b);
	return b;
}

void freeBN(bn_t b) {

	setup();
	bn_free(b);
}

// NOTE: NEVER CALL THIS UNLESS YOU KNOW THE CALLER
// the input must be a string of fixed length
//
bn_t newBNFromHex(char* hex) {
	setup();
	bn_t value = newBN();

	bn_read_str(value, hex, strlen(hex), 16);

	bn_t n;
	bn_null(n);
	bn_new(n);
	g1_get_ord(n);

	bn_mod_basic(value, value, n);

	return value;
}

// NOTE: must free the resulting char*
char* readHexFromBN(bn_t b) {
	setup();
	int len = bn_size_str(b, 16);
	char* str = malloc(len);
	bn_write_str(str, len, b, 16);
	return str;
}

void randBN(bn_t b) {
	setup();
	bn_t n;
	bn_null(n);
	bn_new(n);
	g1_get_ord(n);
	bn_rand_mod(b, n);
	bn_free(n);
}

*/
import "C"

import (
	"fmt"
	"math/big"
	"runtime"
	"unsafe"
)

type BN struct {
	cptr    C.bn_t
	checked bool
}

func NewBN() *BN {
	result := BN{C.newBN(), true}
	runtime.SetFinalizer(&result, clearBN)
	return &result
}

func NewBNFromBig(in *big.Int) *BN {
	str := fmt.Sprintf("%x", in)

	result := NewBNFromHexString(str)
	return result
}

func clearBN(bn *BN) {
	C.freeBN(bn.cptr)
}

func (bn *BN) ToBig() *big.Int {
	chex := C.readHexFromBN(bn.cptr)
	defer C.free(unsafe.Pointer(chex))

	hex := C.GoString(chex)

	i := new(big.Int)
	i.SetString(hex, 16)

	return i
}

func (bn *BN) ToHexString() string {
	// TODO: this process is kinda gross, should directly export bn's
	chex := C.readHexFromBN(bn.cptr)
	defer C.free(unsafe.Pointer(chex))

	return C.GoString(chex)
}

func NewBNFromHexString(hexString string) *BN {
	cstr := C.CString(hexString)
	defer C.free(unsafe.Pointer(cstr))

	result := BN{C.newBNFromHex(cstr), true}
	runtime.SetFinalizer(&result, clearBN)

	return &result
}

// sets BN to a random integer in the modulus order of G1
func (bn *BN) Rand() {
	C.randBN(bn.cptr)
}
