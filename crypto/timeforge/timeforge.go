package timeforge

/*

Public values:
Message   			The text of the message we're signing
PK              	sender public key (computed as PK=g1^{sk})
TPK                 TimeForge server public key (computed as TPK = g2^{tsk})
g1, g2, u, v, h     random generators of the group(s)

Secret values:
sk     sender secret key
t      Signed timestamp
A      Boneh-Boyen signature on timestamp T ( A = g1^{1/{tsk+t}} )

We want to prove the following OR proof:

(g1^x = PK   OR   A = g1^{1/{tsk+t} )

The standard (non-TimeForged) proof will work like this:

1. Pick a random challenge c1 \in Zq
2. Simulate the BB proof exactly the way it's described in Lemma 4.1 of https://crypto.stanford.edu/~dabo/pubs/papers/groupsigs.pdf, using "c1" as "c"
3. Pick a random k \in Zq, set R = g1^k
4. Compute c = Hash(T1 || T2 || T3 || R1 || ... || R5 || PK || TPK || R || Message)
5. Compute c2 = c XOR c1
6. Compute s = x*c2 + k mod q
7. Output the proof as: (T1, T2, T3, R1, ..., R5, R, c2, s)

Verification:

1. Compute c = Hash(T1 || T2 || T3 || R1 || ... || R5 || PK || TPK || R || Message)
2. Compute c1 = c XOR c2
3. Verify the BB proof according to equations (4)-(8) in https://crypto.stanford.edu/~dabo/pubs/papers/groupsigs.pdf, using challenge c1
4. Verify that g1^s == R * PK^{c2}
5. If everything is correct, output TRUE
*/
import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/keyforgery/KeyForge/crypto/bbs"
	"github.com/keyforgery/KeyForge/crypto/liger"
)

type TimeForge struct {
	pub *Public
	sec *Secret
}

type Public struct {
	// G1 vars
	G1 *liger.G1
	U  *liger.G1
	V  *liger.G1
	H  *liger.G1
	// G2 vars
	G2 *liger.G2
	W  *liger.G2
	// pvtk server
	PvtkServer bbs.Public
	PK         *liger.G1
}

type Secret struct {
	Y  *liger.BN
	SK *liger.BN
}

//Generates a new TF instance
func GenerateTimeForge(pkServer bbs.Public) TimeForge {
	var sec Secret
	var pub Public

	sec.Y = liger.NewRandBN()

	sec.SK = liger.NewRandBN()

	pub.G1 = liger.NewG1()
	pub.G2 = liger.NewG2()

	pub.G1.SetGenerator()
	pub.G2.SetGenerator()

	pub.U = liger.NewG1()
	pub.V = liger.NewG1()
	pub.H = liger.NewG1()

	pub.U.Rand()
	pub.V.Rand()
	pub.H.Rand()

	pub.W = liger.NewG2()
	pub.W.Set(pub.G2)
	pub.W.MulBN(sec.Y)
	pub.PvtkServer = pkServer

	pub.PK = liger.CloneG1(pub.G1)
	pub.PK.MulBN(sec.SK)

	return TimeForge{&pub, &sec}
}

// temp
type Sig struct {
	T1  *liger.G1
	T2  *liger.G1
	T3  *liger.G1
	C1  *liger.BN
	C2  *liger.BN
	S   *liger.BN
	Sa  *liger.BN
	Sb  *liger.BN
	Sx  *liger.BN
	Ss1 *liger.BN
	Ss2 *liger.BN
	R   *liger.G1
	S2  *liger.BN
	S3  *liger.BN
	S4  *liger.BN
	T4  *liger.G1
	T5  *liger.G1
	B   *liger.G1
}

func (sig *Sig) String() string {
	var buf bytes.Buffer

	buf.WriteString(sig.T1.Base64())
	buf.WriteString(",")
	buf.WriteString(sig.T2.Base64())
	buf.WriteString(",")
	buf.WriteString(sig.T3.Base64())
	buf.WriteString(",")
	buf.WriteString(sig.C1.ToHexString())
	buf.WriteString(",")
	buf.WriteString(sig.C2.ToHexString())
	buf.WriteString(",")
	buf.WriteString(sig.S.ToHexString())
	buf.WriteString(",")
	buf.WriteString(sig.Sa.ToHexString())
	buf.WriteString(",")
	buf.WriteString(sig.Sb.ToHexString())
	buf.WriteString(",")
	buf.WriteString(sig.Sx.ToHexString())
	buf.WriteString(",")
	buf.WriteString(sig.Ss1.ToHexString())
	buf.WriteString(",")
	buf.WriteString(sig.Ss2.ToHexString())

	return buf.String()
}

func SigFromString(b64in string) (*Sig, error) {
	var result Sig
	var err error
	input := strings.Split(b64in, ",")

	//G1FromBase64(sEnc string) (error, *G1) {
	err, result.T1 = liger.G1FromBase64(input[0])
	if err != nil {
		return nil, err
	}

	err, result.T2 = liger.G1FromBase64(input[1])
	if err != nil {
		return nil, err
	}

	err, result.T3 = liger.G1FromBase64(input[2])
	if err != nil {
		return nil, err
	}

	result.C1 = liger.NewBNFromHexString(input[3])
	result.C2 = liger.NewBNFromHexString(input[4])
	result.Sa = liger.NewBNFromHexString(input[5])
	result.Sb = liger.NewBNFromHexString(input[6])
	result.Sx = liger.NewBNFromHexString(input[7])
	result.Ss1 = liger.NewBNFromHexString(input[8])
	result.Ss2 = liger.NewBNFromHexString(input[9])

	return &result, nil
}

func (tf *TimeForge) getTimeCommitment(t *liger.BN, r *liger.BN) *liger.G1 {
	B := liger.CloneG1(tf.pub.G1)
	B.MulBN(t)
	B2 := liger.CloneG1(tf.pub.H)
	B2.MulBN(r)
	B.Mul(B2)
	return B
}

func (t *TimeForge) Sign(message string) Sig {
	/*
		Overall Strategy:
		1. Pick a random challenge c1 \in Zq
		2. Simulate the BB proof exactly the way it's described in Lemma 4.1 of
		https://crypto.stanford.edu/~dabo/pubs/papers/groupsigs.pdf, using "c1" as "c"
		3. Pick a random k \in Zq, set R = g1^k
		4. Compute c = Hash(T1 || T2 || T3 || R1 || ... || R5 || PK || TPK || R || Message)
		5. Compute c2 = c XOR c1
		6. Compute s = x*c2 + k mod q
		7. Output the proof as: (T1, T2, T3, R1, ..., R5, R, c2, s)
	*/

	// CREATE PETERSON COMMITMENT B:
	time := liger.NewBNFromBig(big.NewInt(time.Now().Unix()))
	r := liger.NewRandBN()
	r.ModP()

	B := t.getTimeCommitment(time, r)

	/////////////////////////////////////////////////////////////////////////////////
	//1. Pick a random challenge c1 \in Zq
	c1 := liger.NewRandBN()
	c1_neg := liger.NewBN()
	c1_neg.Set(c1)
	c1_neg.Neg() // negate bn

	/////////////////////////////////////////////////////////////////////////////////
	// 2. Simulate the BB proof exactly the way it's described in Lemma 4.1 of
	// https://crypto.stanford.edu/~dabo/pubs/papers/groupsigs.pdf, using "c1" as "c"
	alpha := liger.NewRandBN()
	beta := liger.NewRandBN()

	A := liger.NewG1()
	A.Rand()

	T1 := liger.NewG1()
	T2 := liger.NewG1()
	T3 := liger.NewG1()

	T1.Set(t.pub.U)
	T1.MulBN(alpha)

	T2.Set(t.pub.V)
	T2.MulBN(beta)

	helper := liger.NewG1()
	helper.Set(t.pub.H)

	exp := liger.NewBN()
	exp.Set(alpha)
	exp.Add(beta)
	helper.MulBN(exp)

	T3.Set(A)
	T3.Mul(helper)

	sa := liger.NewRandBN()
	sb := liger.NewRandBN()
	sx := liger.NewRandBN()
	ss1 := liger.NewRandBN()
	ss2 := liger.NewRandBN()

	// R1 = u^(sa) * T1^-c
	R1 := liger.NewG1()
	R1.Set(T1)
	R1.MulBN(c1_neg)
	R1_1 := liger.NewG1()
	R1_1.Set(t.pub.U)
	R1_1.MulBN(sa)
	R1.Mul(R1_1)

	// R2:
	R2 := liger.CloneG1(T2)
	R2.MulBN(c1_neg)
	R2_1 := liger.CloneG1(t.pub.V)
	R2_1.MulBN(sb)
	R2.Mul(R2_1)

	// R3:
	// This is going to be epic....
	R3 := liger.Pair(*T3, *t.pub.G2)
	R3.Pow(sx)

	R3_2 := liger.Pair(*t.pub.H, *t.pub.W)
	tempSa := cloneAndNeg(sa)
	tempSb := cloneAndNeg(sb)
	tempSa.Mul(tempSb)
	R3_2.Pow(tempSa)

	R3_3 := liger.Pair(*t.pub.H, *t.pub.G2)
	tempSs1 := cloneAndNeg(ss1)
	tempSs2 := cloneAndNeg(ss2)
	tempSs1.Mul(tempSs2)
	R3_3.Pow(tempSs1)

	R3_4 := liger.Pair(*T3, *t.pub.W)
	R3_4.Div(liger.Pair(*t.pub.G1, *t.pub.G2))
	R3_4.Pow(c1)

	R3.Mul(R3_2)
	R3.Mul(R3_3)
	R3.Mul(R3_4) // This was epic.

	// R4:
	R4 := liger.NewG1()
	R4.Set(T1)
	R4.MulBN(sx)
	R4_1 := liger.NewG1()
	R4_1.Set(t.pub.U)
	tempSs1_1 := liger.NewBN()
	tempSs1_1.Add(ss1)
	tempSs1_1.Neg()
	R4_1.MulBN(tempSs1_1)
	R4.Mul(R4_1)

	// R5:
	R5 := liger.NewG1()
	R5.Set(T2)
	R5.MulBN(sx)
	negSs2 := liger.NewBN()
	negSs2.Add(ss2)
	negSs2.Neg()
	R5_1 := liger.NewG1()
	R5_1.Set(t.pub.V)
	R5_1.MulBN(negSs2)
	R5.Mul(R5_1)
	// wow. That was long.

	/////////////////////////////////////////////////////////////////////////////////
	// 2a. Pick s2 \in Zq and compute T4 = g1^{s_{x}} * h^{s2} / B^{c1}
	s2 := liger.NewRandBN()
	T4 := liger.CloneG1(t.pub.G1)
	T4.MulBN(sx)
	hclone := liger.CloneG1(t.pub.H)
	hclone.MulBN(s2)
	BClone := liger.CloneG1(B)
	BClone.MulBN(c1_neg)
	T4.Mul(BClone)
	T4.Mul(hclone)

	/////////////////////////////////////////////////////////////////////////////////
	// 3. Pick a random k \in Zq, set R = g1^k
	k := liger.NewRandBN()
	R := liger.CloneG1(t.pub.G1)
	R.MulBN(k)

	/////////////////////////////////////////////////////////////////////////////////
	// 4. Compute c = Hash(T1 || T2 || T3 || R1 || ... || R5 || PK || TPK || R || Message)
	h := sha256.New()
	h.Write(T1.Bytes())
	h.Write(T2.Bytes())
	h.Write(T3.Bytes())
	h.Write(R1.Bytes())
	h.Write(R2.Bytes())
	h.Write(R3.Bytes())
	h.Write(R4.Bytes())
	h.Write(R5.Bytes())
	h.Write(t.pub.PK.Bytes())
	h.Write([]byte(t.pub.PvtkServer.String())) // TPK
	h.Write(R.Bytes())
	h.Write([]byte(message))
	shasum := h.Sum(nil) // this is c
	//cBig.SetBytes(shasum)
	//c := liger.NewBNFromBig(cBig)
	//c := liger.NewBN()
	//c.SetBytes(shasum)

	//4a. Compute c3 = Hash(T1 || T2 || T3 || T4 || T5 || R1 || ... || R5 || PK || TPK || R || Message || small) and truncate c3 to 32 bits
	c3n := h.Sum([]byte("1")) // this is c3b
	c3n = c3n[len(c3n)-4:]
	c3 := liger.NewBN()
	c3.SetBytes(c3n)

	/////////////////////////////////////////////////////////////////////////////////
	// 5. Compute c2 = c XOR c1
	result := xorBytes(shasum, c1.Bytes())
	c2 := liger.NewBN()
	c2.SetBytes(result)

	/////////////////////////////////////////////////////////////////////////////////
	//6. Compute s = x*c2 + k mod q
	s := liger.CloneBN(c2)

	s.Mul(t.sec.SK)
	s.Add(k)

	/////////////////////////////////////////////////////////////////////////////////
	// 6a. Compute t1, t2 \in [0...2^256 - 1] and compute T5 = g1^{t1} * h^{t2}
	T5 := liger.CloneG1(t.pub.G1)
	T5_h := liger.CloneG1(t.pub.H)
	t1rand := [32]byte{}
	_, err := rand.Read(t1rand[:])
	if err != nil {
		panic(err)
	}
	t2rand := [32]byte{}
	_, err2 := rand.Read(t2rand[:])
	if err2 != nil {
		panic(err)
	}
	t1 := liger.NewBN()
	t2 := liger.NewBN()
	t1.SetBytes(t1rand[:])
	t2.SetBytes(t2rand[:])

	T5.MulBN(t1)
	T5_h.MulBN(t2)
	T5.Mul(T5_h)

	// 6b. Compute s3 = t*c3 + t1 (not modulo q) and s4 = r*c3 + t2 (not modulo q)
	s3 := liger.CloneBN(c3)
	s3.Mul(time)
	s3.Add(t1)

	s4 := liger.CloneBN(c3)
	s4.Mul(r)
	s4.Add(t2)

	// 7. Output the proof as: (T1, T2, T3, R1, ..., R5, R, c2, s)
	return Sig{T1, T2, T3, c1, c2, s, sa, sb, sx, ss1, ss2, R, s2, s3, s4, T4, T5, B}
}

func cloneAndNeg(bn *liger.BN) *liger.BN {
	neg := liger.CloneBN(bn)
	neg.Neg()
	return neg
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func xorBytes(a, b []byte) []byte {
	if len(a) == 31 {
		// prepend 0
		a = append([]byte{0}, a...)
	}
	if len(b) == 31 {
		// prepend 0
		b = append([]byte{0}, b...)
	}

	result := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		result[i] = a[i] ^ b[i]
	}

	return result
}

func (t *TimeForge) Verify(message string, sig Sig) bool {
	/*
		see: https://crypto.stanford.edu/~dabo/pubs/papers/groupsigs.pdf
		1. Compute R1, R2, R3, R4, R5, and R from what we already have
		2. Compute c = Hash(T1 || T2 || T3 || R1 || ... || R5 || PK || TPK || R || Message)
		3. Verify c1 = c XOR c2
		4. Verify the BB proof according to equations (4)-(8)
		5. Verify that g1^s == R * PK^{c2}
		6. If everything is correct, output TRUE
	*/

	// helper items
	c1_neg := cloneAndNeg(sig.C1)

	// u^s\alpha
	uSA := liger.CloneG1(t.pub.U)
	uSA.MulBN(sig.Sa)
	// u^s\beta
	vSB := liger.CloneG1(t.pub.V)
	vSB.MulBN(sig.Sb)
	// -s\alpha
	// -s\beta
	sasb_neg := cloneAndNeg(sig.Sa)
	sb_neg := cloneAndNeg(sig.Sb)
	sasb_neg.Mul(sb_neg)

	// 0. We need to recompute R, R1, R2, R3, R4, and R5

	// R1 = u^{s_\alpha} / T_1^c1
	R1 := liger.CloneG1(sig.T1)
	R1.MulBN(c1_neg)
	R1.Mul(uSA)

	//R2 = v^{s_\beta} / T_2^c1
	R2 := liger.CloneG1(sig.T2)
	R2.MulBN(c1_neg)
	R2.Mul(vSB)

	//R3 = [e(T_3, g_2) * e(h, w)^{ -s_{\alpha} * -s_{\beta} } *
	//	e(h, g_2)^{-s_{\gamma_1}] * -s{\gamma_2} / [e(g1, g2) / e(T_3, w)]^c1

	R3, numerator, denomPreExp := t.createR3(sig)

	//R4 = T_1^{s_x} * u^{-s_{\gamma_1}}
	R4 := liger.CloneG1(sig.T1)
	R4.MulBN(sig.Sx)
	R4_1 := liger.CloneG1(t.pub.U)
	ss1_neg2 := cloneAndNeg(sig.Ss1)
	R4_1.MulBN(ss1_neg2)
	R4.Mul(R4_1)

	// R5 = T_2^{s_x} * v^{-s_{\gamma_2}}
	R5 := liger.CloneG1(sig.T2)
	R5.MulBN(sig.Sx)
	R5_1 := liger.CloneG1(t.pub.V)
	ss2_neg := cloneAndNeg(sig.Ss2)
	R5_1.MulBN(ss2_neg)
	R5.Mul(R5_1)

	/////////////////////////////////////////////////////////////////////////////////
	//1. Compute c = Hash(T1 || T2 || T3 || R1 || ... || R5 || PK || TPK || R || Message)
	h := sha256.New()
	h.Write(sig.T1.Bytes())
	h.Write(sig.T2.Bytes())
	h.Write(sig.T3.Bytes())
	h.Write(R1.Bytes())
	h.Write(R2.Bytes())
	h.Write(R3.Bytes())
	h.Write(R4.Bytes())
	h.Write(R5.Bytes())
	h.Write(t.pub.PK.Bytes())
	h.Write([]byte(t.pub.PvtkServer.String())) // TPK
	h.Write(sig.R.Bytes())
	h.Write([]byte(message))

	shasum := h.Sum(nil)

	//2a. Compute c3 = Hash(T1 || T2 || T3 || T4 || R1 || ... || R5 || PK || TPK || R || Message || small)
	// and truncate c3 to 32 bits
	c3n := h.Sum([]byte("1")) // this is c3b
	c3n = c3n[len(c3n)-4:]
	c3 := liger.NewBN()
	c3.SetBytes(c3n)

	/////////////////////////////////////////////////////////////////////////////////
	// Verify c1 == c XOR c2
	result := xorBytes(shasum, sig.C2.Bytes())
	comparison := liger.NewBN()
	comparison.SetBytes(result)

	if comparison.Compare(sig.C1) != 0 {
		return false
	}

	/////////////////////////////////////////////////////////////////////////////////
	//Verify the BB proof according to equations (4)-(6)
	// 7 & 8 are definitionally true, as derived above
	c := sig.C1 // bn

	// 1. uSA == T1^sig.C1*R1
	first := liger.CloneG1(sig.T1)
	first.MulBN(c)
	first.Mul(R1)

	if uSA.Equal(first) == false {
		return false
	}

	// 2. vSB == T^c*R2
	second := liger.CloneG1(sig.T2)
	second.MulBN(c)
	second.Mul(R2)

	if vSB.Equal(second) == false {
		return false
	}

	// 3. paring == pairing2^c*R3
	// denomPreExp ^c*R3
	denomPreExp.Pow(c)
	denomPreExp.Mul(R3)
	if numerator.Equal(denomPreExp) == false {
		return false
	}

	/////////////////////////////////////////////////////////////////////////////////
	// 5. Verify that g1^s == R * PK^{c2}
	five := liger.CloneG1(t.pub.G1)
	five.MulBN(sig.S)

	RClone := liger.CloneG1(sig.R)
	PKClone := liger.CloneG1(t.pub.PK)
	PKClone.MulBN(sig.C2)
	RClone.Mul(PKClone)

	if five.Equal(RClone) == false {
		fmt.Println("GOT HERE")
		return false
	}

	// 3a. Verify that g1^{s3} * h^{s4} == B^c3 * T5
	test3a := liger.CloneG1(t.pub.G1)
	test3a.MulBN(sig.S3)
	test3a_m := liger.CloneG1(t.pub.H)
	test3a_m.MulBN(sig.S4)
	test3a.Mul(test3a_m)

	bclone3a := liger.CloneG1(sig.B)
	bclone3a.MulBN(c3)
	bclone3a.Mul(sig.T5)

	if test3a.Equal(bclone3a) == false {
		fmt.Println("GOT HERE")
		return false
	}

	// 3b. Verify that g1^{s_{x}} * h^{s2} == B^{c1} * T4
	test3b := liger.CloneG1(t.pub.G1)
	test3b.MulBN(sig.Sx)
	test3b_m := liger.CloneG1(t.pub.H)
	test3b_m.MulBN(sig.S2)
	test3b.Mul(test3b_m)

	bclone3b := liger.CloneG1(sig.B)
	bclone3b.MulBN(sig.C1)
	bclone3b.Mul(sig.T4)

	if test3b.Equal(bclone3b) == false {
		fmt.Println("GOT HERE")
		return false
	}

	// 6. If everything is correct, output TRUE
	return true
}

func (t *TimeForge) createR3(sig Sig) (*liger.GT, *liger.GT, *liger.GT) {
	sasb_neg := cloneAndNeg(sig.Sa)
	sb_neg := cloneAndNeg(sig.Sb)
	sasb_neg.Mul(sb_neg)

	R3 := liger.Pair(*sig.T3, *t.pub.G2)
	R3.Pow(sig.Sx)

	R3_B := liger.Pair(*t.pub.H, *t.pub.W)
	R3_B.Pow(sasb_neg)

	R3_C := liger.Pair(*t.pub.H, *t.pub.G2)
	ss1_neg := cloneAndNeg(sig.Ss1)
	ss2_neg := cloneAndNeg(sig.Ss2)
	ss1_neg.Mul(ss2_neg)
	R3_C.Pow(ss1_neg)

	R3_D := liger.Pair(*t.pub.G1, *t.pub.G2)
	R3_D_denom := liger.Pair(*sig.T3, *t.pub.W)
	R3_D_denom.Invert()
	R3_D.Mul(R3_D_denom)
	denomPreExp := liger.CloneGT(R3_D) // We can use this part later
	R3_D.Pow(sig.C1)
	R3_D.Invert()

	R3.Mul(R3_B)
	R3.Mul(R3_C)
	numerator := liger.CloneGT(R3) // We can use this part later
	R3.Mul(R3_D)

	return R3, numerator, denomPreExp
}

func hashToBn(message string) *liger.BN {
	h := sha256.New()
	h.Write([]byte(message))
	shasum := h.Sum(nil)
	i := new(big.Int)
	i.SetBytes(shasum)

	return liger.NewBNFromBig(i)

}
