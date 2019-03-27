package liger

/*
#cgo LDFLAGS: -L/usr/local/lib/ -lrelic
#include <relic/relic.h>
#include <stdio.h>

extern int setup();

int gt_comp(gt_t *a, gt_t *b){
	setup();

	if (gt_cmp(*a, *b) == CMP_EQ)
		return 1;
	return 0;
}

void mul_gt(gt_t *g, gt_t *other){
	setup();
	gt_mul(*g, *g, *other);
}


void setIdentity_gt(gt_t *g) {
	setup();
	gt_set_unity(*g);
}

void invert_gt(gt_t *g) {
	setup();
	gt_inv(*g, *g);
}


void power_gt(gt_t *g, bn_t b) {
	setup();
	gt_exp(*g, *g, b);
}

void copy_gt(gt_t *dest, gt_t *src){
	setup();
	gt_copy(*dest, *src);
}

*/
import "C"

// Set sets the value of g to be the same as src.

func (g *GT) Equal(other *GT) bool {
	if uint(C.gt_comp(g.cptr, other.cptr)) == 1 {
		return true
	}
	return false
}

// sets g = g * other
// the group operation on GT elements is a multiplication rather than addition
func (g *GT) Mul(other *GT) {
	C.mul_gt(g.cptr, other.cptr)
}

// sets g = g / other
func (g *GT) Div(other *GT) {
	otherClone := NewGT()
	otherClone.Clone(other)
	otherClone.Invert()
	g.Mul(otherClone)
}

// sets g = 1 / g
func (g *GT) Invert() {
	C.invert_gt(g.cptr)
}

func (g *GT) SetIdentity() {
	C.setIdentity_gt(g.cptr)
}

// Sets g = g^r
func (g *GT) Pow(r *BN) {
	C.power_gt(g.cptr, r.cptr)
}

func (g *GT) Clone(src *GT) {
	C.copy_gt(g.cptr, src.cptr)
}
