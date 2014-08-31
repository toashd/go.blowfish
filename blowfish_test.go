package blowfish

import (
  "bytes"
  "errors"
  "testing"
)

var (
  key = []byte{
    0x79, 0x67, 0x4f, 0x68, 0x6d, 0x31, 0x6d, 0x38,
    0x74, 0x54, 0x67, 0x52, 0x58, 0x4f, 0x6a, 0x4d,
    0x79, 0x54, 0x61, 0x64, 0x5a, 0x4f, 0x76, 0x45,
  }

  iv = []byte{
    0x6c, 0x61, 0x6b, 0x73, 0x6a, 0x64, 0x68, 0x72,
  }

  input = []byte{
    0x6b, 0x52, 0x32, 0x56, 0x61, 0x7a, 0x6f, 0x6d,
    0x67, 0x6f, 0x64, 0x68, 0x31, 0x4b, 0x76, 0x69,
    0x51, 0x72, 0x76, 0x52, 0x36, 0x67, 0x3d, 0x3d,
  }

  output = []byte{
    0x87, 0xb7, 0x0b, 0xc8, 0x67, 0xc9, 0xab, 0xee,
    0x5a, 0xf9, 0xd5, 0xa3, 0xde, 0x7e, 0x97, 0x6f,
    0x2c, 0xfb, 0x39, 0xdb, 0x87, 0xd4, 0xda, 0x3a,
  }

  // Bad ciphertext, plaintext, iv, key (wrong length for any of them)
  badData = []byte{ 0x4d, 0x61, 0x69, 0x74, 0x65 }
)

func TestBlowfish(t *testing.T) {
  result, _ := Encrypt(input, key, iv)
  if !bytes.Equal(result, output) {
    t.Errorf("Failed to get expected output\nwant %x\n and got %x\n", output, result)
  }

  plain, _ := Decrypt(result, key, iv)
  if !bytes.Equal(plain, input) {
    t.Errorf("Failed to get expected output\nwant %x\n and got %x\n", input, plain)
  }
}

func TestEncryptParams(t *testing.T) {
  cases := []struct {
    text []byte
    key  []byte
    iv   []byte
    want error
  }{
    {text: input, key: key, iv: iv, want: nil},
    {text: input, key: key, iv: nil, want: nil},
    {text: badData, key: key, iv: iv, want: errors.New("invalid plaintext length")},
    {text: input, key: badData, iv: iv, want: errors.New("invalid key length")},
    {text: input, key: key, iv: badData, want: errors.New("invalid iv length")},
  }

  for _, tt := range cases {
    _, have := Encrypt(tt.text, tt.key, tt.iv)
    if !sameError(tt.want, have) {
      t.Errorf("Unexpected error condition, have %v want %v", have, tt.want)
    }
  }
}

func TestDecryptParams(t *testing.T) {
  cases := []struct {
    text []byte
    key  []byte
    iv   []byte
    want error
  }{
    {text: output, key: key, iv: iv, want: nil},
    {text: output, key: key, iv: nil, want: nil},
    {text: badData, key: key, iv: iv, want: errors.New("invalid ciphertext length")},
    {text: output, key: badData, iv: iv, want: errors.New("invalid key length")},
    {text: output, key: key, iv: badData, want: errors.New("invalid iv length")},
  }

  for _, tt := range cases {
    _, have := Decrypt(tt.text, tt.key, tt.iv)
    if !sameError(tt.want, have) {
      t.Errorf("Unexpected error condition, have %v want %v", have, tt.want)
    }
  }
}

func TestCheckSizeAndPad(t *testing.T) {
  // TODO
  const in, out = "", ""
  if x := checksizeAndPad(in); x != out {
    t.Errorf("checksizeAndPad(%v) = %v, want %v", in, x, out)
  }
}

func sameError(e1 error, e2 error) bool {
  if e1 == nil || e2 == nil {
    return e1 == nil && e2 == nil
  }
  return e1.Error() == e2.Error()
}

//
// Benchmarks
//

func BenchmarkEncrypt(b *testing.B) {
  for i := 0; i < b.N; i++ {
    Encrypt(input, key, iv)
  }
}

func BenchmarkDecrypt(b *testing.B) {
  for i := 0; i < b.N; i++ {
    Decrypt(output, key, iv)
  }
}
