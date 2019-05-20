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

	bn_mod(value, value, n);
	bn_free(n);

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

void modG1(bn_t b) {
	setup();
	bn_t n;
	bn_null(n);
	bn_new(n);
	g1_get_ord(n);
	bn_mod(b,b,n);
	bn_free(n);
}


void addOtherBN(bn_t b, bn_t other){
	setup();
	bn_add(b, b, other);
}

void mulOtherBN(bn_t b, bn_t other){
	setup();
	bn_mul(b, b, other);
}

void powOtherBN(bn_t b, bn_t other){
	setup();
	bn_t n;
	bn_null(n);
	bn_new(n);
	g1_get_ord(n);

	bn_mxp(b, b, other, n);
	bn_free(n);
}

void negBN(bn_t b){
	setup();
	bn_neg(b, b);
}

void invertBN(bn_t b){
	setup();
	bn_t r;
	bn_t n;
	bn_null(n);
	bn_null(r);
	bn_new(n);
	bn_new(r);

	g1_get_ord(n);
	// This is a super odd way for this to work, but it does
	bn_gcd_ext(r, b, NULL, b, n);
	if (bn_sign(b) == RLC_NEG) {
		bn_add(b,b,n);
	}
	bn_free(r);
	bn_free(n);
}

void copyBN(bn_t dest, bn_t src) {
	setup();
	bn_copy(dest, src);
}

int compareBN(bn_t left, bn_t right){
	setup();
	int result = bn_cmp(left, right);
	if (result == RLC_LT){
		return -1;
	}
	if (result == RLC_GT){
		return 1;
	}
	if (result == RLC_EQ){
		return 0;
	}
	return -1;
}

void bnToBytes(char* dest, bn_t src, int len) {
	setup();
	bn_write_bin((uint8_t*)dest, len, src); // 1 indicates compression
}

void bnFromBytes(bn_t dest, char* src,  int len) {
	setup();
	bn_read_bin(dest, (uint8_t*)src, len);
}

int getBNBytesLen(bn_t bn) {
	setup();
	return bn_size_bin(bn);
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

func NewRandBN() *BN {
	result := NewBN()
	result.Rand()
	return result
}

func CloneBN(other *BN) *BN {
	result := NewBN()
	result.Set(other)
	return result
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

// Set sets the value of g to be the same as src.
func (bn *BN) Set(src *BN) {
	C.copyBN(bn.cptr, src.cptr)
}

// sets BN to a random integer in the modulus order of G1
func (bn *BN) Rand() {
	C.randBN(bn.cptr)
}

// this = this + other
func (bn *BN) Add(other *BN) {
	C.addOtherBN(bn.cptr, other.cptr)
}

// this = this * other
func (bn *BN) Mul(other *BN) {
	C.mulOtherBN(bn.cptr, other.cptr)
}

// this = this ^ other
func (bn *BN) Pow(other *BN) {
	C.powOtherBN(bn.cptr, other.cptr)
}

// Multiplicative inverse (GCD mod N)
func (bn *BN) Invert() {
	C.invertBN(bn.cptr)
}

// Multiplicative inverse (GCD mod N)
func (bn *BN) Neg() {
	C.negBN(bn.cptr)
}

// Returns 1 if bn > other, -1 if bn < other, and 0 if equal
func (bn *BN) Compare(other *BN) int {
	return int(C.compareBN(bn.cptr, other.cptr))
}

func (bn *BN) BytesLen() uint {
	return uint(C.getBNBytesLen(bn.cptr))
}

// Exports as a byte sequence.
func (bn *BN) Bytes() []byte {
	length := bn.BytesLen()
	buf := make([]byte, length)
	C.bnToBytes((*C.char)(unsafe.Pointer(&buf[0])), bn.cptr, C.int(length))
	return buf
}

// SetBytes imports a sequence exported by Bytes() and sets the value of g.
func (bn *BN) SetBytes(buf []byte) {
	cbytes := C.CBytes(buf)
	defer C.free(cbytes)

	C.bnFromBytes(bn.cptr, (*C.char)(cbytes), C.int(len(buf)))
}

// this = this Mod the order of G1
func (bn *BN) ModP() {
	C.modG1(bn.cptr)
}
