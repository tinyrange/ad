package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

type Signer struct {
	ed25519.PrivateKey
}

func (s *Signer) Sign(data []byte) string {
	result := ed25519.Sign(s.PrivateKey, data)

	return base64.RawURLEncoding.EncodeToString(result)
}

func (s *Signer) Public() string {
	key := s.PrivateKey.Public().(ed25519.PublicKey)

	return base64.RawURLEncoding.EncodeToString(key)
}

func Verify(pub string, data []byte, sig string) bool {
	signature, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return false
	}

	key, err := base64.RawURLEncoding.DecodeString(pub)
	if err != nil {
		return false
	}

	return ed25519.Verify(key, data, signature)
}

func GenerateKey() (*Signer, error) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}

	return &Signer{PrivateKey: priv}, nil
}

type FlagGenerator struct {
	Prefix string
	Suffix string
}

func (gen *FlagGenerator) Generate(tickId int, teamId int, serviceId int, key *Signer) string {
	data := fmt.Sprintf("%d.%d.%d", tickId, teamId, serviceId)

	sig := key.Sign([]byte(data))

	return fmt.Sprintf("%s%s.%s%s", gen.Prefix, data, sig, gen.Suffix)
}

func (gen *FlagGenerator) Verify(public string, flag string) (tickId int, teamId int, serviceId int, ok bool) {
	var err error

	tickId = -1
	teamId = -1
	serviceId = -1
	ok = false

	if !strings.HasPrefix(flag, gen.Prefix) || !strings.HasSuffix(flag, gen.Suffix) {
		return
	}

	flag = strings.TrimSuffix(strings.TrimPrefix(flag, gen.Prefix), gen.Suffix)

	tokens := strings.Split(flag, ".")

	if len(tokens) != 4 {
		return
	}

	tickId, err = strconv.Atoi(tokens[0])
	if err != nil {
		return
	}

	teamId, err = strconv.Atoi(tokens[1])
	if err != nil {
		return
	}

	serviceId, err = strconv.Atoi(tokens[2])
	if err != nil {
		return
	}

	sig := tokens[3]

	data := fmt.Sprintf("%d.%d.%d", tickId, teamId, serviceId)

	ok = Verify(public, []byte(data), sig)

	return
}

func NewFlagGenerator(prefix, suffix string) *FlagGenerator {
	return &FlagGenerator{Prefix: prefix, Suffix: suffix}
}
