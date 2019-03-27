package liger

/*
#cgo LDFLAGS: -L/usr/local/lib/ -lrelic

#include <relic/relic.h>
#include <relic/relic_pc.h>
#include <relic/relic_util.h>
#include <relic/relic_label.h>
#include <relic/relic_conf.h>

int setup(){
	if (core_get() != NULL)
		return 0; // already initialized

	if (core_init() != STS_OK)
		return -1;
	pc_param_set_any();
	return 0;
}


g1_t newG1() {
	setup();
	g1_t g;
	g1_null(g)
	g1_new(g);
	g1_set_infty(g);
	return g;
}


g2_t newG2() {
	setup();
	g2_t g;
	g2_null(g);
	g2_new(g);
	return g;
}

gt_t* newGT() {
	setup();
	// the gt_* macros are bizzare because gt_t is actually an array.
    gt_t gtemp;
    gt_t *g = (gt_t*) malloc(sizeof(gt_t));
    gt_null(gtemp);
    gt_new(gtemp);
    memcpy(g, &gtemp, sizeof(*g));
    return g;
}

void freeG1(g1_t x) {
	setup();
	g1_free(x);
}
void freeG2(g2_t x) {
	setup();
	g2_free(x);
}
void freeGT(gt_t *x) {
	// Dealing with dumb macros
	setup();
    gt_t temp;
    memcpy(*temp, x, sizeof(*x));
    gt_free(temp);
    free(x);
}

void setG1Rand(g1_t g) {
	setup();
	g1_rand(g);
}
void setG2Rand(g2_t g) {
	setup();
	g2_rand(g);
}

void printG1(g1_t g) { g1_print(g);}
void printG2(g2_t g) { g2_print(g);}


void pair(gt_t* in, g1_t g1, g2_t g2){
	pc_map(*in, g1, g2);
}

// Handles the multi-product optimization
void pair_product(gt_t* in, g1_t* g1, g2_t* g2, int len){
	pc_map_sim(*in, g1, g2, len);
}

size_t pointerSize(){
	gt_t *t;
	return sizeof(t);
}

*/
import "C"

import (
	"errors"
	"runtime"
	"unsafe"
)

type G1 struct {
	cptr    C.g1_t
	checked bool
}

type G2 struct {
	cptr    C.g2_t
	checked bool
}

type GT struct {
	cptr    *C.gt_t
	checked bool
}

func NewG1() *G1 {
	result := G1{C.newG1(), true}
	runtime.SetFinalizer(&result, clearG1)
	return &result
}

func NewG2() *G2 {
	result := G2{C.newG2(), true}
	runtime.SetFinalizer(&result, clearG2)
	return &result
}

func NewGT() *GT {
	result := GT{C.newGT(), true}
	runtime.SetFinalizer(&result, clearGT)
	return &result
}

func clearG1(g1 *G1) {
	C.freeG1(g1.cptr)
}

func clearG2(g2 *G2) {
	C.freeG2(g2.cptr)
}

func clearGT(gt *GT) {
	C.freeGT(gt.cptr)
}

func (g *G1) Rand() {
	C.setG1Rand(g.cptr)
}

func (g *G2) Rand() {
	C.setG2Rand(g.cptr)
}

func (g *G1) Print() {
	C.printG1(g.cptr)
}

func (g *G2) Print() {
	C.printG2(g.cptr)
}

func Pair(g1 G1, g2 G2) *GT {
	newGT := NewGT()
	C.pair(newGT.cptr, g1.cptr, g2.cptr)

	return newGT
}

// Calculates the pairing of all of elements in g1 and g2 and multiplies them
// In other words: Π e(g1[i], g2[i]) for all 0 <= i < len(g1)
func ProductPair(g1 []*G1, g2 []*G2) (*GT, error) {

	if len(g1) != len(g2) {
		return nil, errors.New("Product pairs must be of equal length")
	}

	newGT := NewGT()
	length := len(g1)

	// Turning a c-array into a slice
	// From https://github.com/golang/go/wiki/cgo#turning-c-arrays-into-go-slices
	var g1ArrayPointer = C.calloc(C.size_t(length), C.sizeof_g1_t)
	var g2ArrayPointer = C.calloc(C.size_t(length), C.sizeof_g2_t)
	defer C.free(g1ArrayPointer)
	defer C.free(g2ArrayPointer)

	var g1CArray *C.g1_t = (*C.g1_t)(g1ArrayPointer)
	var g2CArray *C.g2_t = (*C.g2_t)(C.calloc(C.size_t(length), C.sizeof_g2_t))

	g1Slice := (*[1 << 28]C.g1_t)(unsafe.Pointer(g1CArray))[:length:length]
	g2Slice := (*[1 << 28]C.g2_t)(unsafe.Pointer(g2CArray))[:length:length]

	for i := 0; i < length; i++ {
		// Set g1 pointer
		g1Slice[i] = g1[i].cptr
		g2Slice[i] = g2[i].cptr
	}

	C.pair_product(newGT.cptr, g1CArray, g2CArray, C.int(length))

	return newGT, nil
}
