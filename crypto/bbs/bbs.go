package bbs

/*
The following is a BBS short signature scheme via the LIGER bridge
See: "Short Signatures Without Random Oracles"
http://ai.stanford.edu/~xb/eurocrypt04a/bbsigs.pdf

*/
import (
	"bytes"
	"crypto/sha256"
	"math/big"
	"strings"

	"github.com/keyforgery/KeyForge/crypto/liger"
)

type BBS struct {
	Pub *Public
	Sec *Secret
}

type Public struct {
	G1 *liger.G1
	G2 *liger.G2
	U  *liger.G2
	V  *liger.G2
	Z  *liger.GT
}

/////////////////////////////////////////////////////////////////////////////////
// Pk export as a string
func (pub *Public) String() string {

	var buf bytes.Buffer
	buf.WriteString(pub.G1.Base64())
	buf.WriteString(",")
	buf.WriteString(pub.G2.Base64())
	buf.WriteString(",")
	buf.WriteString(pub.U.Base64())
	buf.WriteString(",")
	buf.WriteString(pub.V.Base64())
	buf.WriteString(",")
	buf.WriteString(pub.Z.Base64())

	return buf.String()
}

func PublicFromString(b64in string) (*Public, error) {
	input := strings.Split(b64in, ",")
	var result Public
	var err error

	//G1FromBase64(sEnc string) (error, *G1) {
	err, result.G1 = liger.G1FromBase64(input[0])
	if err != nil {
		return nil, err
	}

	err, result.G2 = liger.G2FromBase64(input[1])
	if err != nil {
		return nil, err
	}

	err, result.U = liger.G2FromBase64(input[2])
	if err != nil {
		return nil, err
	}

	err, result.U = liger.G2FromBase64(input[3])
	if err != nil {
		return nil, err
	}

	err, result.V = liger.G2FromBase64(input[4])
	if err != nil {
		return nil, err
	}

	err, result.Z = liger.GTFromBase64(input[5])
	if err != nil {
		return nil, err
	}

	return &result, nil
}

type Secret struct {
	X *liger.BN
	Y *liger.BN
}

/////////////////////////////////////////////////////////////////////////////////
// secret export as a string
func (sec *Secret) String() string {
	var buf bytes.Buffer
	buf.WriteString(sec.X.ToHexString())
	buf.WriteString(",")
	buf.WriteString(sec.Y.ToHexString())

	return buf.String()
}

func SecretFromString(b64in string) *Secret {
	var result Secret
	input := strings.Split(b64in, ",")

	//G1FromBase64(sEnc string) (error, *G1) {
	result.X = liger.NewBNFromHexString(input[0])
	result.Y = liger.NewBNFromHexString(input[1])
	return &result
}

type Sig struct {
	Sigma *liger.G1 // signature point
	R     *liger.BN
}

//Generates a new BBS
func GenerateBBS() BBS {
	var sec Secret
	var pub Public

	sec.X = liger.NewBN()
	sec.Y = liger.NewBN()

	sec.X.Rand()
	sec.Y.Rand()

	pub.G1 = liger.NewG1()
	pub.G2 = liger.NewG2()

	pub.G1.SetGenerator()
	pub.G2.SetGenerator()

	pub.Z = liger.Pair(*pub.G1, *pub.G2)

	pub.U = liger.NewG2()
	pub.V = liger.NewG2()
	pub.U.Set(pub.G2)
	pub.V.Set(pub.G2)

	pub.U.MulBN(sec.X)
	pub.V.MulBN(sec.Y)

	return BBS{&pub, &sec}
}

func hashToBn(message string) *liger.BN {
	h := sha256.New()
	h.Write([]byte(message))
	shasum := h.Sum(nil)
	i := new(big.Int)
	i.SetBytes(shasum)

	return liger.NewBNFromBig(i)

}

func (bbs *BBS) Sign(message string) Sig {
	// Hashing the message
	// This may be slow, but it at least guarantees that the message is < p
	m := hashToBn(message)

	// random element mod the order of G1 (and therefore G2)
	r := liger.NewBN()
	r.Rand()

	s := liger.NewBN()

	// sig = G-1 ^ 1/(x+m+y*r)
	s.Add(r)
	s.Mul(bbs.Sec.Y)
	s.Add(bbs.Sec.X)
	s.Add(m)
	s.Invert()

	sig := liger.NewG1()
	sig.Set(bbs.Pub.G1)
	sig.MulBN(s)

	return Sig{sig, r}
}

func (pub *Public) Verify(message string, signature Sig) bool {

	// e(sigma, U*g_2^m * V^R)
	u := liger.NewG2()
	v := liger.NewG2()
	u.Set(pub.U)
	v.Set(pub.V)

	g2 := liger.NewG2()
	g2.Set(pub.G2)

	m := hashToBn(message)
	g2.MulBN(m)
	v.MulBN(signature.R)

	// NOTE: addition <=> multiplication as a group element
	g2.Add(v)
	g2.Add(u)
	result := liger.Pair(*signature.Sigma, *g2)

	return pub.Z.Equal(result)
}

/////////////////////////////////////////////////////////////////////////////////
// Signature functions
/*
func (sig *Sig) ToString() string {
	// TODO
	return nil
}

func (sig *Sig) FromString(input string) error {
	// TODO
	return nil
}
*/
