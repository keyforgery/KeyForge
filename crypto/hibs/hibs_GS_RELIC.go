package hibs

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/big"
	"sync"

	"github.com/keyforgery/KeyForge/crypto/liger"
)

// The main struct for all Gentry Silverberg HIBE/S operations
type GSHIBE struct {
	publicSetup  bool // Have the public parameters been set?
	privateSetup bool // Have the private parameters been set?
	Params       *Parameters
	MasterSecret *liger.BN
	Roots        map[string]*Entity
	hashCache    struct {
		sync.RWMutex
		m map[string]*liger.G1
	}
}

// Public parameters for the GSHIBE scheme
type Parameters struct {
	// point generator, should be a member of G1
	P0      *liger.G2
	Q0      *liger.G2
	QValues []*liger.G2 // Public parameter values
}

// An entity is an individual node in an GSHIBE tree
type Entity struct {
	PrivKey   *liger.BN
	PrivPoint *liger.G1
	Public    *liger.G1 // hash(ID) -> G_2 for this node
	ID        string
	Children  map[string]*Entity
	parent    *Entity
	QValues   []*liger.G2 // All Q values from the parents
}

// returns a b64 encoded metadata required for this node to be verified
func (e *Entity) Params() string {
	// Last Q value only
	value := e.QValues[len(e.QValues)-1]
	return base64.StdEncoding.EncodeToString(value.Bytes())
}

// returns a b64 encoded metadata required for this node to be verified
func (e *Entity) Parent() *Entity {
	// Last Q value only
	return e.parent
}

type Ciphertext struct {
	U0      *liger.G2
	UValues []*liger.G1
	V       []byte
}

type GSSig struct {
	Sig     *liger.G1   // signature point
	QValues []*liger.G2 // Public parameter values
}

// Recreates a signature from b64 encoded signature string and qvalue strings
func GSSigFromPublic(sig string, qvalues []string) (error, *GSSig) {

	sigDecode, err := base64.StdEncoding.DecodeString(sig)

	if err != nil {
		return err, nil
	}

	newSig := liger.NewG1()
	newSig.SetBytes(sigDecode)

	qv := make([]*liger.G2, len(qvalues))

	for i, value := range qvalues {
		qDecode, err2 := base64.StdEncoding.DecodeString(value)
		if err2 != nil {
			return err, nil
		}

		qi := liger.NewG2()
		qi.SetBytes(qDecode)

		qv[i] = qi
	}

	return nil, &GSSig{newSig, qv}
}

func (h *GSHIBE) ExportSign(m string, ID []string, include int) (sig string, qvalues []string) {
	val := h.Sign(m, ID)

	for _, val := range val.QValues {
		bytes := val.Bytes()
		qvalues = append(qvalues, base64.StdEncoding.EncodeToString(bytes))
	}
	fmt.Println(qvalues)

	qvalues = qvalues[len(val.QValues)-include:]

	sig = base64.StdEncoding.EncodeToString(val.Sig.Bytes())

	return
}

func (h *GSHIBE) Sign(m string, ID []string) GSSig {
	// Extract to the ID
	entity := h.ExtractPath(ID)

	// we bit prefix m with an ascii '1' for signing
	s_t := h.PublicKeyHash(m, true)
	s_t.MulBN(entity.PrivKey)

	// sig
	sig := liger.NewG1()
	sig.Set(entity.PrivPoint)
	sig.Add(s_t)

	return GSSig{sig, entity.QValues}
}

// Verifies a signature s
func (h *GSHIBE) Verify(s GSSig, message string, ID []string) bool {

	P_M := h.PublicKeyHash(message, true)
	P_1 := h.PublicKeyHash(ID[0], false)

	Q_t := s.QValues[len(s.QValues)-1]

	g2Vals := make([]*liger.G2, 0, len(ID))
	g1Vals := make([]*liger.G1, 0, len(ID))

	//mul := liger.NewGT()
	//mul.SetIdentity()

	for i := 1; i < len(ID); i++ {
		P_i := h.PublicKeyHash(ID[i], false)
		Q_i := s.QValues[i-1]

		//current := liger.Pair(*Q_i, *P_i)
		g2Vals = append(g2Vals, Q_i)
		g1Vals = append(g1Vals, P_i)

		//mul.Mul(current)
	}

	//mul.Mul(liger.Pair(*Q_t, *P_M))
	g2Vals = append(g2Vals, Q_t)
	g1Vals = append(g1Vals, P_M)

	//mul.Mul(liger.Pair(*h.Params.Q0, *P_1))
	g2Vals = append(g2Vals, h.Params.Q0)
	g1Vals = append(g1Vals, P_1)

	// sig
	comparee := liger.Pair(*s.Sig, *h.Params.P0)

	mul, err := liger.ProductPair(g1Vals, g2Vals)
	if err != nil {
		// Productpair failed =(
		return false
	}

	return comparee.Equal(mul)
}

func (h *GSHIBE) Encrypt(IDS []string, message []byte) *Ciphertext {
	var P1 *liger.G1
	var PT *liger.G1
	var p []*liger.G1

	r := liger.NewBN()
	r.Rand()

	current := liger.NewG2()
	current.Set(h.Params.P0)
	current.MulBN(r)

	for i, ID := range IDS {
		PT = h.PublicKeyHash(ID, false)

		if i == 0 {
			P1 = PT
		} else {
			PT.MulBN(r)
			p = append(p, PT)
		}
	}

	//gr := liger.Pair(*h.Params.Q0, *P1)
	gr := liger.Pair(*P1, *h.Params.Q0)
	gr.Pow(r)
	result := hashAndXor(message, gr)

	return &Ciphertext{current, p, result}
}

func (h *GSHIBE) Decrypt(IDS []string, cipher *Ciphertext) (message []byte) {
	leaf := h.ExtractPath(IDS)

	U0 := cipher.U0
	UValues := cipher.UValues[:]

	denom, err := liger.ProductPair(UValues, leaf.QValues[:len(UValues)])
	if err != nil {
		panic("product pair failed")
	}
	denom.Invert() // 1/denominator

	numerator := liger.Pair(*leaf.PrivPoint, *U0)
	numerator.Mul(denom) // numerator / denominator

	result := hashAndXor(cipher.V, numerator)

	return result
}

// Extract as defined in our modified scheme
func (h *GSHIBE) Extract(ID string, parent *Entity) *Entity {
	var entityMap map[string]*Entity
	var lastST *liger.G1
	var lastS *liger.BN

	if parent == nil {
		// we're making a child node from the root
		var entity Entity
		parent = &entity
		parent.QValues = make([]*liger.G2, 0)
		entityMap = h.Roots
		lastST = liger.NewG1()
		lastST.SetIdentity()
		lastS = h.MasterSecret
	} else {
		entityMap = parent.Children
		lastST = parent.PrivPoint
		lastS = parent.PrivKey
	}

	currentEntity, nodeExists := entityMap[ID]

	if nodeExists {
		return currentEntity
	}

	// Create a node if one doesn't exist for this ID

	// 1. Compute PT = H(ID_t) -> G1
	PT := h.PublicKeyHash(ID, false)

	// 2. Select a secret Zr integer s_t, this is the "secret"
	// In a usual implementation, this would be private.Rand()
	// Instead, we do something slightly more tricky:
	// private := h(private_{i-1} || id)
	hash := sha256.New()
	hash.Write([]byte(ID))
	hash.Write(lastS.ToBig().Bytes())

	z := new(big.Int)
	z.SetBytes(hash.Sum(nil))
	private := liger.NewBNFromBig(z)

	// 3. Secret point S_t = S_{t-1} + s_{t-1}*PT
	temp := liger.NewG1()
	temp.Set(PT)
	temp.MulBN(lastS)

	NewSt := liger.NewG1()
	NewSt.Set(lastST)
	NewSt.Add(temp)

	// 4. Q_t = s_t*P0
	QT := liger.NewG2()
	QT.Set(h.Params.P0)
	QT.MulBN(private)

	// Add this entity to our list
	var newEntity Entity
	newEntity.PrivKey = private
	newEntity.PrivPoint = NewSt
	newEntity.Public = PT
	newEntity.Children = make(map[string]*Entity)
	newEntity.QValues = make([]*liger.G2, 0)
	newEntity.QValues = append(newEntity.QValues, parent.QValues...)
	newEntity.QValues = append(newEntity.QValues, QT)

	newEntity.parent = parent
	entityMap[ID] = &newEntity
	return &newEntity
}

// Helper function that will extract from the root to the leaf and return the
// final leaf entity
func (h *GSHIBE) ExtractPath(IDS []string) (leaf *Entity) {
	for _, ID := range IDS {
		leaf = h.Extract(ID, leaf)
	}

	return
}

func (h *GSHIBE) Setup() {
	var hibeParams Parameters

	P0 := liger.NewG2()
	P0.Rand()

	private := liger.NewBN()
	private.Rand()

	Q0 := liger.NewG2()
	Q0.Set(P0)
	Q0.MulBN(private)

	hibeParams.P0 = P0
	hibeParams.Q0 = Q0
	h.publicSetup = true
	h.privateSetup = true
	h.MasterSecret = private
	h.Roots = make(map[string]*Entity)
	h.Params = &hibeParams
}

// Returns a b64 encoded string of the entities that make up the public params
func (h *GSHIBE) ExportPublic() string {

	P0bytes := h.Params.P0.Bytes()
	Q0bytes := h.Params.Q0.Bytes()

	bufQ0 := make([]byte, len(Q0bytes)+4)
	binary.BigEndian.PutUint32(bufQ0, uint32(len(Q0bytes)))

	bufP0 := make([]byte, len(P0bytes)+4)
	binary.BigEndian.PutUint32(bufP0, uint32(len(P0bytes)))

	copy(bufP0[4:], P0bytes)
	copy(bufQ0[4:], Q0bytes)

	bigBuf := append(bufP0, bufQ0...)

	return base64.StdEncoding.EncodeToString(bigBuf)
}

// Returns a b64 encoded string of the private key
func (h *GSHIBE) ExportMasterPrivate() string {
	return base64.StdEncoding.EncodeToString([]byte(h.MasterSecret.ToHexString()))
}

// Returns a b64 encoded string of the private key of a particular ID
func (h *GSHIBE) ExportLeafPrivate(IDS []string) string {
	entity := h.ExtractPath(IDS)
	return base64.StdEncoding.EncodeToString([]byte(entity.PrivKey.ToHexString()))
}

// Imports from the b64 encoded public parameters in encodedPK
func (h *GSHIBE) SetupPublicFromString(encodedPK string) error {
	var hibeParams Parameters

	decode, err := base64.StdEncoding.DecodeString(encodedPK)
	if err != nil {
		fmt.Println("ERROR")
		return err
	}
	// Encoded as l, v, lengths are big endian

	lenP0 := binary.BigEndian.Uint32(decode[0:])
	lenQ0 := binary.BigEndian.Uint32(decode[lenP0+4:])

	P0bytes := decode[4 : lenP0+4]
	Q0bytes := decode[lenP0+8:]
	Q0bytes = Q0bytes[:lenQ0]

	P0 := liger.NewG2()
	Q0 := liger.NewG2()

	P0.SetBytes(P0bytes)
	Q0.SetBytes(Q0bytes)

	hibeParams.P0 = P0
	hibeParams.Q0 = Q0

	h.Params = &hibeParams

	h.publicSetup = true
	return nil
}

// Imports from the b64 encoded private parameters in encodedSK
func (h *GSHIBE) SetupPrivateFromString(encodedSK string) error {

	decodeS, err := base64.StdEncoding.DecodeString(encodedSK)

	if err != nil {
		return err
	}

	private := liger.NewBNFromHexString(string(decodeS))

	h.MasterSecret = private
	h.Roots = make(map[string]*Entity)

	h.privateSetup = true

	return nil
}
