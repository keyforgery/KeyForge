package liger

/*
#cgo LDFLAGS: -L/usr/local/lib/ -lrelic
#include <relic/relic.h>
extern int setup();

void copyGT(gt_t* dest, gt_t* src){
	setup();
	gt_copy(*dest, *src);
}

int getGTCompressedSz(gt_t* g) {
	setup();
	return gt_size_bin(*g, 1);
}

void gTToBytes(char* dest, gt_t* src, int len) {
	setup();
	gt_write_bin((uint8_t*)dest, len, *src,  1); // 1 indicates compression
}

void gTFromBytes(gt_t* dest, char* src,  int len) {
	setup();
	gt_read_bin(*dest, (uint8_t*)src, len);
}

*/
import "C"
import (
	"encoding/base64"
	"unsafe"
)

// Set sets the value of g to be the same as src.
func (g *GT) Set(src *GT) {
	C.copyGT(g.cptr, src.cptr)
}

func CloneGT(other *GT) *GT {
	result := NewGT()
	result.Set(other)
	return result
}

// Exports as b64 encoded string
func (g *GT) Base64() string {
	return base64.StdEncoding.EncodeToString(g.Bytes())
}

func GTFromBase64(sEnc string) (error, *GT) {
	g := NewGT()
	sDec, err := base64.StdEncoding.DecodeString(sEnc)

	if err != nil {
		return err, nil
	}

	g.SetBytes(sDec)
	return nil, g
}

// Bytes exports GT as a byte sequence.
func (g *GT) Bytes() []byte {
	length := g.BytesLen()
	buf := make([]byte, length)
	C.gTToBytes((*C.char)(unsafe.Pointer(&buf[0])), g.cptr, C.int(length))
	return buf
}

// SetBytes imports a sequence exported by Bytes() and sets the value of g.
func (g *GT) SetBytes(buf []byte) {
	cbytes := C.CBytes(buf)
	defer C.free(cbytes)

	C.gTFromBytes(g.cptr, (*C.char)(cbytes), C.int(len(buf)))
}

// CompressedBytes exports GT in a compressed form as a byte sequence.
// Alias of Bytes
func (g *GT) CompressedBytes() []byte {
	return g.Bytes()
}

// SetCompressedBytes imports a sequence exported by CompressedBytes() and sets
// the value of g.
func (g *GT) SetCompressedBytes(buf []byte) {
	g.SetBytes(buf)
}

func (g *GT) GetCompressedSize() uint {
	return uint(C.getGTCompressedSz(g.cptr))
}

func (g *GT) BytesLen() uint {
	return g.GetCompressedSize()
}
