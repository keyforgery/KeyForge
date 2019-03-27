package liger

import (
	"fmt"
	"math/big"
	"testing"
)

func TestCopy(t *testing.T) {
	src := NewG1()
	src.Rand()
	dest := NewG1()
	dest.Set(src)

	if !src.Equal(dest) {
		t.Fail()
	}
}

func TestBNSet(t *testing.T) {
	a := big.NewInt(1234)

	b := NewBNFromBig(a)

	c := b.ToBig()

	if a.Cmp(c) != 0 {
		str := fmt.Sprintf("%x", &a)
		t.Log(str)
		t.Log("Setting BN failed")
		t.Fail()
	}

}

func TestG1Hash(t *testing.T) {

	a := NewG1()
	a.SetFromString("TEST")

	b := NewG1()
	b.SetFromString("TEST")

	if !a.Equal(b) {
		t.Fail()
	}

	b.SetFromString("TEST2") // should be different

	if a.Equal(b) {
		t.Fail()
	}

}

func TestGT(t *testing.T) {
	g1 := NewG1()
	g1.Rand()

	g2 := NewG2()
	g2.Rand()

	gt := Pair(*g1, *g2)

	gt2 := NewGT()
	gt2.Clone(gt)

	gt.Mul(gt) // double itself

	// GT and GT2 should be different
	if gt.Equal(gt2) {
		t.Fail()
	}

	gt.Div(gt2)

	// GT and GT2 should be the same
	if !gt.Equal(gt2) {
		t.Fail()
	}

	// testing stability of exponentiation
	bn := NewBN()
	bn.Rand() // some bn in zr

	gt.Pow(bn)

	if gt.Equal(gt2) {
		t.Fail()
	}

	gt2.Pow(bn)

	if !gt.Equal(gt2) {
		t.Fail()
	}
	// test identity

	gt3 := NewGT()
	gt3.SetIdentity()
	gt.Mul(gt3)

	if !gt.Equal(gt2) {
		t.Fail()
	}

}

//func ProductPair(g1 []G1, g2 []G2) (*GT, error) {
func TestProductPair(t *testing.T) {
	g1Slice := make([]*G1, 100)
	g2Slice := make([]*G2, 100)

	for i := 0; i < 100; i++ {
		g1 := NewG1()
		g1.Rand()
		g2 := NewG2()
		g2.Rand()
		g1Slice[i] = g1
		g2Slice[i] = g2
	}

	gt := NewGT()
	gt.SetIdentity()
	// ground truth:
	for i := 0; i < 100; i++ {
		current := Pair(*g1Slice[i], *g2Slice[i])
		gt.Mul(current)
	}

	test, err := ProductPair(g1Slice, g2Slice)

	if err != nil {
		//
		t.Log("fail, product pair returned an error", err)
		t.Fail()
	}

	if !test.Equal(gt) {
		t.Log("Failure, products should be equal")
		t.Fail()
	}
}

func getRand(n int) ([]*G1, []*G2) {
	g1Slice := make([]*G1, n)
	g2Slice := make([]*G2, n)

	for i := 0; i < n; i++ {
		g1 := NewG1()
		g1.Rand()
		g2 := NewG2()
		g2.Rand()
		g1Slice[i] = g1
		g2Slice[i] = g2
	}
	return g1Slice, g2Slice

}

func BenchmarkRand(b *testing.B) {
	getRand(b.N)
}

func BenchmarkPairProduct(b *testing.B) {
	g1Slice := make([]*G1, b.N)
	g2Slice := make([]*G2, b.N)

	for i := 0; i < b.N; i++ {
		g1 := NewG1()
		g1.Rand()
		g2 := NewG2()
		g2.Rand()
		g1Slice[i] = g1
		g2Slice[i] = g2
	}
	b.ResetTimer()
	gt := NewGT()
	gt.SetIdentity()
	// ground truth:
	for i := 0; i < b.N; i++ {
		current := Pair(*g1Slice[i], *g2Slice[i])
		gt.Mul(current)
	}
}

func BenchmarkPairProductOpt(b *testing.B) {
	g1Slice := make([]*G1, b.N)
	g2Slice := make([]*G2, b.N)

	for i := 0; i < b.N; i++ {
		g1 := NewG1()
		g1.Rand()
		g2 := NewG2()
		g2.Rand()
		g1Slice[i] = g1
		g2Slice[i] = g2
	}

	b.ResetTimer()
	ProductPair(g1Slice, g2Slice)
}
