package bbs

import (
	"fmt"
	"testing"
)

func TestExportImport(t *testing.T) {
}

func TestSignAndVerify(t *testing.T) {
	bbs := GenerateBBS()

	msg := "askldfjwoiqj"
	sig := bbs.Sign(msg)

	if bbs.Pub.Verify(msg, sig) == false {
		fmt.Print("Didn't verify!")
		t.Fail()
	}

	msg2 := "Should not verify"
	if bbs.Pub.Verify(msg2, sig) {
		t.Fail()
	}

}
