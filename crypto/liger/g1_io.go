package liger

/*
#cgo LDFLAGS: -L/usr/local/lib/ -lrelic
#include <relic/relic.h>
extern int setup();

void copyG1(g1_t dest, g1_t src) {
	setup();
	g1_copy(dest, src);
}

int getG1CompressedSz(g1_t g) {
	setup();
	return g1_size_bin(g,1);
}

void g1Map(g1_t dest, char* src, int len){
	setup();
	 g1_map(dest, (uint8_t*)src, len);
}

void g1ToBytes(char* dest, g1_t src, int len) {
	setup();
	g1_write_bin((uint8_t*)dest, len, src,  1); // 1 indicates compression
}

void g1FromBytes(g1_t dest, char* src,  int len) {
	setup();
	g1_read_bin(dest, (uint8_t*)src, len);
}

*/
import "C"
import (
	"encoding/base64"
	"hash"
	"unsafe"
)

// Set sets the value of g to be the same as src.
func (g *G1) Set(src *G1) {
	C.copyG1(g.cptr, src.cptr)
}

func CloneG1(other *G1) *G1 {
	result := NewG1()
	result.Set(other)
	return result
}

// Deterministically maps a string onto a point in g1
func (g *G1) SetFromStringHash(s string, h hash.Hash) {
	if _, err := h.Write([]byte(s)); err != nil {
		panic("hash failed!")
	}
	hashString := string(h.Sum([]byte{})[:h.Size()])

	g.SetFromString(hashString)
}

// Deterministically maps a string onto a point in g1
func (g *G1) SetFromString(s string) {
	result := C.CString(s)
	defer C.free(unsafe.Pointer(result))
	C.g1Map(g.cptr, result, C.int(len(s)))
}

// Exports as b64 encoded string
func (g *G1) Base64() string {
	return base64.StdEncoding.EncodeToString(g.Bytes())
}

func G1FromBase64(sEnc string) (error, *G1) {
	g := NewG1()
	sDec, err := base64.StdEncoding.DecodeString(sEnc)

	if err != nil {
		return err, nil
	}

	g.SetBytes(sDec)
	return nil, g
}

// Exports as a byte sequence.
func (g *G1) Bytes() []byte {
	length := g.BytesLen()
	buf := make([]byte, length)
	C.g1ToBytes((*C.char)(unsafe.Pointer(&buf[0])), g.cptr, C.int(length))
	return buf
}

// SetBytes imports a sequence exported by Bytes() and sets the value of g.
func (g *G1) SetBytes(buf []byte) {
	cbytes := C.CBytes(buf)
	defer C.free(cbytes)

	C.g1FromBytes(g.cptr, (*C.char)(cbytes), C.int(len(buf)))
}

// CompressedBytes exports el in a compressed form as a byte sequence.
// Alias of Bytes
func (g *G1) CompressedBytes() []byte {
	return g.Bytes()
}

// SetCompressedBytes imports a sequence exported by CompressedBytes() and sets
// the value of g.
func (g *G1) SetCompressedBytes(buf []byte) {
	g.SetBytes(buf)
}

func (g *G1) GetCompressedSize() uint {
	return uint(C.getG1CompressedSz(g.cptr))
}

func (g *G1) BytesLen() uint {
	return g.GetCompressedSize()
}
