package liger

/*
#cgo LDFLAGS: -L/usr/local/lib/ -lrelic
#include <relic/relic.h>
extern int setup();

void copyG2(g2_t dest, g2_t src) {
setup();
	g2_copy(dest, src);
}

int getG2CompressedSz(g2_t g) {
	setup();
	return g2_size_bin(g,1);
}

void g2Map(g2_t dest, char* src, int len){

	setup();
	g2_map(dest, (uint8_t*)src, len);
}

void g2ToBytes(char* dest, g2_t src, int len) {
	setup();
	g2_write_bin((uint8_t*)dest, len, src,  1); // 1 indicates compression
}

void g2FromBytes(g2_t dest, char* src,  int len) {
	setup();
	g2_read_bin(dest, (uint8_t*)src, len);
}

*/
import "C"
import (
	"hash"
	"unsafe"
)

// Set sets the value of g to be the same as src.
func (g *G2) Set(src *G2) {
	C.copyG2(g.cptr, src.cptr)
}

// Deterministically maps a string onto a point in g1
func (g *G2) SetFromStringHash(s string, h hash.Hash) {
	if _, err := h.Write([]byte(s)); err != nil {
		panic("hash failed!")
	}
	hashString := string(h.Sum([]byte{})[:h.Size()])

	g.SetFromString(hashString)
}

// Deterministically maps a string onto a point in g2
func (g *G2) SetFromString(s string) {
	result := C.CString(s)
	defer C.free(unsafe.Pointer(result))
	C.g2Map(g.cptr, result, C.int(len(s)))
}

// Bytes exports el as a byte sequence.
func (g *G2) Bytes() []byte {
	length := g.BytesLen()
	buf := make([]byte, length)
	C.g2ToBytes((*C.char)(unsafe.Pointer(&buf[0])), g.cptr, C.int(length))
	return buf
}

// SetBytes imports a sequence exported by Bytes() and sets the value of g.
func (g *G2) SetBytes(buf []byte) {
	cbytes := C.CBytes(buf)
	defer C.free(cbytes)

	C.g2FromBytes(g.cptr, (*C.char)(cbytes), C.int(len(buf)))
}

// CompressedBytes exports el in a compressed form as a byte sequence.
// Alias of Bytes
func (g *G2) CompressedBytes() []byte {
	return g.Bytes()
}

// SetCompressedBytes imports a sequence exported by CompressedBytes() and sets
// the value of g.
func (g *G2) SetCompressedBytes(buf []byte) {
	g.SetBytes(buf)
}

func (g *G2) GetCompressedSize() uint {
	return uint(C.getG2CompressedSz(g.cptr))
}

func (g *G2) BytesLen() uint {
	return g.GetCompressedSize()
}
