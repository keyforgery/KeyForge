package hibs

import (
	"crypto/sha256"

	"github.com/keyforgery/KeyForge/crypto/liger"
	"golang.org/x/crypto/sha3"
)

// generates h2, which is a hash H_2 -> G_2 -> {0,1}^n
func longHashGen(input []byte, bytes int) []byte {
	// Shake 256 *must* generate more than 64 bytes of info
	// see https://godoc.org/golang.org/x/crypto/sha3
	if bytes < 64 {
		bytes = 64
	}

	h := make([]byte, bytes)
	sha3.ShakeSum256(h, input)
	return h
}

func hashAndXor(message []byte, entity *liger.GT) []byte {
	longHash := longHashGen(entity.Bytes(), len(message))

	result := make([]byte, len(message))
	for i := 0; i < len(message); i++ {
		result[i] = message[i] ^ longHash[i]
	}

	return result
}

// Helper function that provides a liger point hash for a particular message
// id = the id string, signing is whether or not this is for a signing key
func (h *GSHIBE) PublicKeyHash(id string, isSigning bool) *liger.G1 {
	if isSigning {
		id = "0" + id
		// if we are signing, then this is unlikely to be asked again
		// SO, let's not cache
		result := liger.NewG1()
		result.SetFromStringHash(id, sha256.New())

		return result
	} else {
		id = "1" + id
	}

	if h.hashCache.m == nil {
		h.hashCache.m = make(map[string]*liger.G1)
	}

	// check if the hash is in our hash cache
	// Get read lock
	//h.hashCache.RLock()
	value, isInCache := h.hashCache.m[id]
	if isInCache {
		//	h.hashCache.RUnlock()
		result := liger.NewG1()
		result.Set(value)
		return value
	}
	// This is not cached =(
	//h.hashCache.RUnlock()

	// Get write lock
	//h.hashCache.Lock()
	//defer h.hashCache.Unlock()

	// Calculate the hash and map to a member of g2
	result := liger.NewG1()
	result.SetFromStringHash(id, sha256.New())

	h.hashCache.m[id] = liger.NewG1()
	h.hashCache.m[id].Set(result)

	return result
}
