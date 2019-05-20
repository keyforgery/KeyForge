package timeforge

import (
	"math/rand"
	"testing"
	"time"

	"github.com/keyforgery/KeyForge/crypto/bbs"
)

func TestExportImport(t *testing.T) {
}

func TestSignAndVerify(t *testing.T) {
	pvtk := bbs.GenerateBBS()

	msg := "askldfjwoiqj"
	sig := pvtk.Sign(msg)

	if pvtk.Pub.Verify(msg, sig) == false {
		t.Fail()
	}

	msg2 := "Should not verify"
	if pvtk.Pub.Verify(msg2, sig) {
		t.Fail()
	}

	// Generate TF:
	tf := GenerateTimeForge(*pvtk.Pub)

	tfsig := tf.Sign(msg)

	if tf.Verify(msg, tfsig) == false {
		t.Fail()
	}

}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func RandStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func BenchmarkSign(b *testing.B) {

	// Set randomness
	rand.Seed(time.Now().UnixNano())

	pvtk := bbs.GenerateBBS()
	tf := GenerateTimeForge(*pvtk.Pub)

	// Generate a random 64-byte string to sign (64 == len(any sha256 result))
	message := make([]string, b.N)

	for i := 0; i < b.N; i++ {
		message[i] = RandStringRunes(64)
	}

	// Reset timer
	b.ResetTimer()

	/////////////////////////////////////////////////////
	// Benchmark
	for i := 0; i < b.N; i++ {
		tf.Sign(message[i])
	}

}

func BenchmarkVerify(b *testing.B) {

	// Set randomness
	rand.Seed(time.Now().UnixNano())

	pvtk := bbs.GenerateBBS()
	tf := GenerateTimeForge(*pvtk.Pub)

	// Generate a random 64-byte string to sign (64 == len(any sha256 result))
	message := make([]string, b.N)
	sigs := make([]Sig, b.N)

	for i := 0; i < b.N; i++ {
		message[i] = RandStringRunes(64)
		sigs[i] = tf.Sign(message[i])
	}

	// Reset timer
	b.ResetTimer()

	/////////////////////////////////////////////////////
	// Benchmark
	for i := 0; i < b.N; i++ {
		tf.Verify(message[i], sigs[i])
	}

}
