package capture

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"testing"
)

// TestDeriveInitialKeys — тестовые векторы RFC 9001 A.2 (клиент) и A.3
// (сервер): DCID 8394c8f03e515708, salt QUIC v1.
// Заодно это единственная проверка hkdfExpandLabel: формат метки
// "tls13 client in", порядок salt/IKM в Extract, длины 16/12/16.
func TestDeriveInitialKeys(t *testing.T) {
	dcid, err := hex.DecodeString("8394c8f03e515708")
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		server  bool
		wantKey string
		wantIV  string
		wantHP  string
	}{
		{
			name:    "client (RFC 9001 A.2)",
			wantKey: "1f369613dd76d5467730efcbe3b1a22d",
			wantIV:  "fa044b2f42a3fd3b46fb255c",
			wantHP:  "9f50449e04a0e810283a1e9933adedd2",
		},
		{
			name:    "server (RFC 9001 A.3)",
			server:  true,
			wantKey: "cf3a5331653c364c88f0f379b6067e37",
			wantIV:  "0ac1493ca1905853b0bba03e",
			wantHP:  "c206b8d9b9f0f37644430b490eeaa314",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, iv, hp, err := deriveInitialKeys(dcid, tc.server)
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(key); got != tc.wantKey {
				t.Errorf("key:\n got  %s\n want %s", got, tc.wantKey)
			}
			if got := hex.EncodeToString(iv); got != tc.wantIV {
				t.Errorf("iv:\n got  %s\n want %s", got, tc.wantIV)
			}
			if got := hex.EncodeToString(hp); got != tc.wantHP {
				t.Errorf("hp:\n got  %s\n want %s", got, tc.wantHP)
			}
		})
	}
}

// TestReadVarint — таблица из RFC 9000 §16 + обрезанные значения
// (после рефакторинга readVarint обязан отдавать n==0, а не паниковать).
func TestReadVarint(t *testing.T) {
	cases := []struct {
		hex   string
		value uint64
		n     int
	}{
		{"00", 0, 1},
		{"01", 1, 1},
		{"3f", 63, 1},
		{"4040", 64, 2},
		{"7fff", 16383, 2},
		{"80004000", 16384, 4},
		{"bfffffff", 1073741823, 4},
		{"c000000040000000", 1073741824, 8},
		{"dfffffffffffffff", 2305843009213693951, 8},
		{"c2197c5eff14e88c", 151288809941952652, 8},
	}
	for _, tc := range cases {
		b, err := hex.DecodeString(tc.hex)
		if err != nil {
			t.Fatal(err)
		}
		if v, n := readVarint(b); v != tc.value || n != tc.n {
			t.Errorf("%s: got (%d, %d), want (%d, %d)", tc.hex, v, n, tc.value, tc.n)
		}
	}

	// Обрезанные varint — n == 0, без паники.
	for _, b := range [][]byte{{}, {0x40}, {0x80, 0x00, 0x00}, {0xc0}} {
		if v, n := readVarint(b); n != 0 {
			t.Errorf("%x: обрезанный varint дал n=%d (v=%d)", b, n, v)
		}
	}
}

// TestDecryptInitialRoundTrip — самосогласованность: собираем Initial
// вручную (Seal + защита заголовка) и прогоняем через
// parseQUICInitial + decryptInitial.
//
// Честности ради: симметричную ошибку в AAD такой тест не поймает
// (шифровали и расшифровывали бы с одним и тем же багом) — для этого
// векторы A.2 выше. Зато он ловит ошибки монтажа: смещение sample,
// позицию PN, XOR-маску флагов, nonce, границы ProtectedPart.
func TestDecryptInitialRoundTrip(t *testing.T) {
	dcid, _ := hex.DecodeString("8394c8f03e515708")
	scid, _ := hex.DecodeString("06f6f626172")
	plaintext := []byte("crypto frame placeholder")

	const (
		flags = 0xC1 // long header, Initial, pnLen = 2
		pn    = 0x1234
	)
	pnBytes := []byte{byte(pn >> 8), byte(pn & 0xFF)}

	key, iv, hp, err := deriveInitialKeys(dcid, false)
	if err != nil {
		t.Fatal(err)
	}

	// Заголовок с НЕзащищёнными флагами. Длина < 64 — 1-байтовый varint.
	length := len(pnBytes) + len(plaintext) + 16 // PN + payload + тег
	if length >= 64 {
		t.Fatal("тест рассчитан на 1-байтовый varint длины")
	}
	hdr := []byte{flags, 0x00, 0x00, 0x00, 0x01, byte(len(dcid))}
	hdr = append(hdr, dcid...)
	hdr = append(hdr, byte(len(scid)))
	hdr = append(hdr, scid...)
	hdr = append(hdr, 0x00, byte(length)) // token length = 0, length

	// Nonce и AAD — зеркально decryptInitial.
	nonce := make([]byte, len(iv))
	copy(nonce, iv)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(uint64(pn) >> (8 * i))
	}
	aad := append(append([]byte{}, hdr...), pnBytes...)

	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(aesBlock)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)

	// Защита заголовка: sample — 16 байт с offset 4 от начала PN.
	protected := append(append([]byte{}, pnBytes...), ciphertext...)
	hpBlock, err := aes.NewCipher(hp)
	if err != nil {
		t.Fatal(err)
	}
	sample := protected[4 : 4+16]
	var mask [16]byte
	hpBlock.Encrypt(mask[:], sample)

	packet := append([]byte{}, hdr...)
	packet[0] ^= mask[0] & 0x0F // флаги
	protected[0] ^= mask[1]     // PN, байт 0
	protected[1] ^= mask[2]     // PN, байт 1
	packet = append(packet, protected...)

	// Разбор и расшифровка.
	info, ok := parseQUICInitial(packet)
	if !ok {
		t.Fatal("parseQUICInitial не распознал собранный пакет")
	}
	got, err := decryptInitial(info, false)
	if err != nil {
		t.Fatalf("decryptInitial: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext не совпал:\n got  %q\n want %q", got, plaintext)
	}
}
