package main

import (
	"crypto/ed25519"
	"testing"
)

var (
	TEST_PRIVATE_SEED = ed25519.PrivateKey{
		0x1f, 0x2a, 0x3b, 0x4c, 0x5d, 0x6e, 0x7f, 0x80,
		0x91, 0xa2, 0xb3, 0xc4, 0xd5, 0xe6, 0xf7, 0x08,
		0x19, 0x2a, 0x3b, 0x4c, 0x5d, 0x6e, 0x7f, 0x80,
		0x91, 0xa2, 0xb3, 0xc4, 0xd5, 0xe6, 0xf7, 0x08,
	}

	TEST_PRIVATE_KEY = ed25519.NewKeyFromSeed(TEST_PRIVATE_SEED)

	TEST_SIGNER = &Signer{PrivateKey: TEST_PRIVATE_KEY}
)

func TestGenerateKey(t *testing.T) {
	signer, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("hello, world!")
	sig := signer.Sign(data)

	if !Verify(signer.Public(), data, sig) {
		t.Fatal("signature verification failed")
	}
}

func TestSigner(t *testing.T) {
	data := []byte("hello, world!")
	sig := TEST_SIGNER.Sign(data)

	if !Verify(TEST_SIGNER.Public(), data, sig) {
		t.Fatal("signature verification failed")
	}
}

func TestGenerateFlag(t *testing.T) {
	gen := NewFlagGenerator("flag{", "}")

	flag := gen.Generate(0, 1, 2, TEST_SIGNER)

	expected := "flag{0.1.2.wdnk4iF4bRt1CEEcUhuvKTxpNDm53IuOkEEnleBz1mHPXqafU6qF4R5K-4YjXOgAreSGr2lHJ7pUN2dsirv-Cg}"

	if flag != expected {
		t.Fatalf("expected flag %s, got %s", expected, flag)
	}
}

func TestVerifyFlag(t *testing.T) {
	gen := NewFlagGenerator("flag{", "}")

	public := TEST_SIGNER.Public()

	flag := "flag{0.1.2.wdnk4iF4bRt1CEEcUhuvKTxpNDm53IuOkEEnleBz1mHPXqafU6qF4R5K-4YjXOgAreSGr2lHJ7pUN2dsirv-Cg}"

	tickId, teamId, serviceId, ok := gen.Verify(public, flag)
	if !ok {
		t.Fatal("failed to verify flag")
	}

	if tickId != 0 || teamId != 1 || serviceId != 2 {
		t.Fatal("failed to match flag contents")
	}
}
