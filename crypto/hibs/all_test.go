package hibs

import (
	"encoding/base64"
	"fmt"
	"math/rand"
	"testing"
	"time"
)

func TestExport(t *testing.T) {
	var h1 GSHIBE
	var h2 GSHIBE
	h1.Setup()

	public := h1.ExportPublic()
	private := h1.ExportMasterPrivate()

	h2.SetupPublicFromString(public)
	h2.SetupPrivateFromString(private)

	// h1 and h2's params should be equivalent
	msBig1 := h1.MasterSecret.ToBig()
	msBig2 := h2.MasterSecret.ToBig()

	if msBig1.Cmp(msBig2) != 0 {
		// Master secrets aren't equal
		fmt.Println("import export failed")
		t.Fail()
	}

	if !h2.Params.Q0.Equal(h1.Params.Q0) {
		fmt.Println("import export failed")
		t.Fail()

	}

	if !h2.Params.P0.Equal(h1.Params.P0) {
		fmt.Println("import export failed")
		t.Fail()
	}

}

func TestCopy(t *testing.T) {
	var h GSHIBE
	h.Setup()

	s := "winning"

	//path := [...]string{"a", "b", "c", "d"}
	path := [...]string{"year", "month", "day", "second", "whatever"}
	cipher := h.Encrypt(path[:], []byte(s))
	msg := string(h.Decrypt(path[:], cipher))

	if msg != s {
		t.Log(msg)
		t.Fail()
	}
}

func TestSign(t *testing.T) {
	var h GSHIBE

	h.Setup()

	m := "winning"

	path := [...]string{"year", "month", "day", "second", "whatever"}
	signature := h.Sign(m, path[:])

	if !h.Verify(signature, m, path[:]) {
		t.Log("Signature failed to verify =(")
		t.Fail()
	}

	m2 := "This should not verify"

	if h.Verify(signature, m2, path[:]) {
		t.Log("Signature verified when it shouldn't =(")
		t.Fail()
	}
	param := signature.QValues[0].Bytes()

	fmt.Println("Sig Size", signature.Sig.GetCompressedSize())
	fmt.Println("Param Size", signature.QValues[0].GetCompressedSize())
	fmt.Println("Param b64Size", len(base64.StdEncoding.EncodeToString(param)))
	fmt.Println("Secret Key Size", len(h.MasterSecret.ToHexString()))
	fmt.Println("Secret Key b64Size", len(base64.StdEncoding.EncodeToString([]byte(h.MasterSecret.ToHexString()))))

}

func TestSign2(t *testing.T) {
	var h GSHIBE

	h.Setup()

	m := "winning"

	path := [...]string{"year", "month", "day", "second", "whatever"}
	signature := h.Sign(m, path[:])

	if !h.Verify(signature, m, path[:]) {
		t.Log("Signature failed to verify =(")
		t.Fail()
	}

	m2 := "This should not verify"

	if h.Verify(signature, m2, path[:]) {
		t.Log("Signature verified when it shouldn't =(")
		t.Fail()
	}
	fmt.Println("Sig Size", signature.Sig.GetCompressedSize())
	fmt.Println("Param Size", signature.QValues[0].GetCompressedSize())
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func RandStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

/////////////////////////////////////////////////////
// Benchmark signing
func benchlsign(levels int, b *testing.B) {
	/////////////////////////////////////////////////////
	// Initialization:

	// Set randomness
	rand.Seed(time.Now().UnixNano())

	// set up hibe
	var h GSHIBE
	h.Setup()

	// Generate a size l string, two chars each
	path := make([][]string, b.N)

	// Generate a random 64-byte string to sign (64 == len(any sha256 result))
	message := make([]string, b.N)

	for i := 0; i < b.N; i++ {
		path[i] = make([]string, levels)
		for j := 0; j < levels; j++ {
			path[i][j] = RandStringRunes(2)
		}
		message[i] = RandStringRunes(64)
	}

	// Reset timer
	b.ResetTimer()

	/////////////////////////////////////////////////////
	// Benchmark
	for i := 0; i < b.N; i++ {
		h.Sign(message[i], path[i][:])
	}
}

func benchlsignNotRandom(levels int, b *testing.B) {
	/////////////////////////////////////////////////////
	// Initialization:

	// Set randomness
	rand.Seed(time.Now().UnixNano())

	// set up hibe
	var h GSHIBE
	h.Setup()

	// Generate a size l string, two chars each
	path := make([]string, levels)

	for i := 0; i < levels; i++ {
		path[i] = RandStringRunes(2)
	}

	// Generate a random 64-byte string to sign (64 == len(any sha256 result))
	message := make([]string, b.N)

	for i := 0; i < b.N; i++ {
		message[i] = RandStringRunes(64)
	}

	pathSlice := path[:]

	// Reset timer
	b.ResetTimer()

	/////////////////////////////////////////////////////
	// Benchmark
	for i := 0; i < b.N; i++ {
		h.Sign(message[i], pathSlice)
	}
}

func BenchmarkL1Sign(b *testing.B) { benchlsignNotRandom(1, b) }
func BenchmarkL2Sign(b *testing.B) { benchlsignNotRandom(2, b) }
func BenchmarkL3Sign(b *testing.B) { benchlsignNotRandom(3, b) }
func BenchmarkL4Sign(b *testing.B) { benchlsignNotRandom(4, b) }
func BenchmarkL5Sign(b *testing.B) { benchlsignNotRandom(5, b) }
func BenchmarkL6Sign(b *testing.B) { benchlsignNotRandom(6, b) }
func BenchmarkL7Sign(b *testing.B) { benchlsignNotRandom(7, b) }

func BenchmarkL1SignRandom(b *testing.B) { benchlsign(1, b) }
func BenchmarkL2SignRandom(b *testing.B) { benchlsign(2, b) }
func BenchmarkL3SignRandom(b *testing.B) { benchlsign(3, b) }
func BenchmarkL4SignRandom(b *testing.B) { benchlsign(4, b) }
func BenchmarkL5SignRandom(b *testing.B) { benchlsign(5, b) }
func BenchmarkL6SignRandom(b *testing.B) { benchlsign(6, b) }
func BenchmarkL7SignRandom(b *testing.B) { benchlsign(7, b) }

/////////////////////////////////////////////////////
// Benchmark verification

func benchLevelVerifyNotRandom(levels int, b *testing.B) {
	/////////////////////////////////////////////////////
	// Initialization:

	// Set randomness
	rand.Seed(time.Now().UnixNano())

	// set up hibe
	var h GSHIBE
	h.Setup()

	// Generate a size l string, two chars each
	path := make([]string, levels)

	for i := 0; i < levels; i++ {
		path[i] = RandStringRunes(2)
	}

	sigs := make([]*GSSig, b.N)
	message := make([]string, b.N)

	for i := 0; i < b.N; i++ {
		// Generate a random 64-byte string to sign (64 == len(any sha256 result))
		message[i] = RandStringRunes(64)
		sig := h.Sign(message[i], path[:])
		sigs[i] = &sig
	}

	pathSlice := path[:]

	// Reset timer
	b.ResetTimer()

	/////////////////////////////////////////////////////
	// Benchmark
	for i := 0; i < b.N; i++ {
		h.Verify(*sigs[i], message[i], pathSlice)
	}
}

func benchLevelVerifyRandom(levels int, b *testing.B) {
	/////////////////////////////////////////////////////
	// Initialization:

	// Set randomness
	rand.Seed(time.Now().UnixNano())

	// set up hibe
	var h GSHIBE
	h.Setup()

	// Generate a size l string, two chars each
	path := make([][]string, b.N)

	// Generate a random 64-byte string to sign (64 == len(any sha256 result))
	message := make([]string, b.N)
	sigs := make([]GSSig, b.N)

	for i := 0; i < b.N; i++ {
		path[i] = make([]string, levels)
		for j := 0; j < levels; j++ {
			path[i][j] = RandStringRunes(2)
		}
		message[i] = RandStringRunes(64)
		sigs[i] = h.Sign(message[i], path[i][:])
	}

	// Reset timer
	b.ResetTimer()

	/////////////////////////////////////////////////////
	// Benchmark
	for i := 0; i < b.N; i++ {
		h.Verify(sigs[i], message[i], path[i][:])
	}
}

func BenchmarkL1Verify(b *testing.B) { benchLevelVerifyNotRandom(1, b) }
func BenchmarkL2Verify(b *testing.B) { benchLevelVerifyNotRandom(2, b) }
func BenchmarkL3Verify(b *testing.B) { benchLevelVerifyNotRandom(3, b) }
func BenchmarkL4Verify(b *testing.B) { benchLevelVerifyNotRandom(4, b) }
func BenchmarkL5Verify(b *testing.B) { benchLevelVerifyNotRandom(5, b) }
func BenchmarkL6Verify(b *testing.B) { benchLevelVerifyNotRandom(6, b) }
func BenchmarkL7Verify(b *testing.B) { benchLevelVerifyNotRandom(7, b) }

func BenchmarkL1VerifyRandom(b *testing.B) { benchLevelVerifyRandom(1, b) }
func BenchmarkL2VerifyRandom(b *testing.B) { benchLevelVerifyRandom(2, b) }
func BenchmarkL3VerifyRandom(b *testing.B) { benchLevelVerifyRandom(3, b) }
func BenchmarkL4VerifyRandom(b *testing.B) { benchLevelVerifyRandom(4, b) }
func BenchmarkL5VerifyRandom(b *testing.B) { benchLevelVerifyRandom(5, b) }
func BenchmarkL6VerifyRandom(b *testing.B) { benchLevelVerifyRandom(6, b) }
func BenchmarkL7VerifyRandom(b *testing.B) { benchLevelVerifyRandom(7, b) }
