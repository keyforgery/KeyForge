package liger

/*
#cgo LDFLAGS: -L/usr/local/lib/ -lrelic
#include <relic/relic.h>
#include <stdio.h>
extern int setup();

int g2_comp(g2_t a, g2_t b){
	setup();
	if (g2_cmp(a, b) == RLC_EQ)
		return 1;
	return 0;
}

void g2_mulBN(g2_t g, bn_t other){
	setup();
	g2_mul(g, g, other);
}

void g2_addPoint(g2_t g, g2_t other){
	setup();
	g2_add(g, g, other);
}


void setIdentity_g2(g2_t g) {
	setup();
	g2_set_infty(g);
}

*/
import "C"

func (g *G2) SetIdentity() {
	C.setIdentity_g2(g.cptr)
}

func (g *G2) Equal(other *G2) bool {
	if uint(C.g2_comp(g.cptr, other.cptr)) == 1 {
		return true
	}
	return false
}

func (g *G2) MulBN(other *BN) {
	C.g2_mulBN(g.cptr, other.cptr)
}

// sets g = g + other
func (g *G2) Add(other *G2) {
	C.g2_addPoint(g.cptr, other.cptr)
}
