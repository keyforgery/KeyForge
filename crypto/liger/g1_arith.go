package liger

/*
#cgo LDFLAGS: -L/usr/local/lib/ -lrelic
#include <relic/relic.h>
#include <stdio.h>

extern int setup();
int g1_comp(g1_t a, g1_t b){
	setup();
	if (g1_cmp(a, b) == CMP_EQ)
		return 1;
	return 0;
}

void mulBN(g1_t g, bn_t other){
	setup();
	g1_mul(g, g, other);
}

void addPoint(g1_t g, g1_t other){
	setup();
	g1_add(g, g, other);
}


void setIdentity_g1(g1_t g) {
	setup();
	g1_set_infty(g);
}

*/
import "C"

func (g *G1) SetIdentity() {
	C.setIdentity_g1(g.cptr)
}

func (g *G1) Equal(other *G1) bool {
	if uint(C.g1_comp(g.cptr, other.cptr)) == 1 {
		return true
	}
	return false
}

func (g *G1) MulBN(other *BN) {
	C.mulBN(g.cptr, other.cptr)
}

// sets g = g + other
func (g *G1) Add(other *G1) {
	C.addPoint(g.cptr, other.cptr)
}
