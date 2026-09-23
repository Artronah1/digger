package capture

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestDeriveInitialKeys(t *testing.T) {
	dcid, _ := hex.DecodeString("8394c8f03e515708")
	key, iv, hp, err := deriveInitialKeys(dcid, false)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("client key=%x\n", key)
	fmt.Printf("client iv=%x\n", iv)
	fmt.Printf("client hp=%x\n", hp)
	// Ожидаем по RFC 9001 A.2:
	// key = 1f369613dd76d5467730efcbe3b1a22d
	// iv  = fa044b2f42a3fd3b46fb255c
	// hp  = 9f50449e04a0e810283a1e9933adedd2
}

func TestDeriveServerKeys(t *testing.T) {
	dcid, _ := hex.DecodeString("8394c8f03e515708")
	key, iv, hp, err := deriveInitialKeys(dcid, true)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("server key=%x\n", key)
	fmt.Printf("server iv=%x\n", iv)
	fmt.Printf("server hp=%x\n", hp)
	// Ожидаем по RFC 9001 A.3:
	// key = cf3a5331653c364c88f0f379b6067e37
	// iv  = 0ac1493ca1905853b0bba03e
	// hp  = c206b8d9b9f0f37644430b490eeaa314
}
