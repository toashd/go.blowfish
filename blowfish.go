package blowfish

import (
  "code.google.com/p/go.crypto/blowfish"
  "crypto/cipher"
  "errors"
)

var defaultIV = []byte{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }

// Encrypt encrypts plaintext and returns ciphertext.
// plaintext's length must be a multiple of 8. key is a 24 byte key.
// iv is an 8 byte initialization vector. If iv is nil, zeros
// will be used as the initialization vector.
func Encrypt(plaintext, key, iv []byte) ([]byte, error) {

  switch {
  case iv == nil:
    iv = defaultIV
  case len(iv) != 8:
    return nil, errors.New("invalid iv length")
  }

  // check size and pad if necessary
  plaintext = checksizeAndPad(plaintext)

  // create the cipher
  ecipher, err := blowfish.NewCipher(key)
  if err != nil {
    panic(err)
  }

  // make ciphertext big enough to store len(plaintext) + blowfish.BlockSize
  ciphertext := make([]byte, blowfish.BlockSize+len(plaintext))

  // make initialization vector to be the first 8 bytes of ciphertext
  iv = ciphertext[:blowfish.BlockSize]

  // create encrypter
  ecbc := cipher.NewCBCEncrypter(ecipher, iv)

  // encrypt blocks
  ecbc.CryptBlocks(ciphertext[blowfish.BlockSize:], plaintext)

  // return ciphertext
  return ciphertext, nil
}

// Decrypt decrypts ciphertext and returns plaintext.
// ciphertext's length must be a multiple of 8. key is a 24 byte des key.
// iv is an 8 byte initialization vector. If iv is nil, zeros
// will be used as the initialization vector.
func Decrypt(ciphertext, key, iv []byte) ([]byte, error) {

  switch {
  case len(ciphertext)%8 != 0:
    return nil, errors.New("invalid ciphertext length")
  case iv == nil:
    iv = defaultIV
  case len(iv) != 8:
    return nil, errors.New("invalid iv length")
  }

  // create the cipher
  dcipher, err := blowfish.NewCipher(key)
  if err != nil {
    panic(err)
  }

  // make initialization vector to be the first 8 bytes of ciphertext
  iv = ciphertext[:blowfish.BlockSize]

  // check last slice of encrypted text, if it's not a modulus of cipher block size, we're in trouble
  decrypted := ciphertext[blowfish.BlockSize:]
  if len(decrypted) % blowfish.BlockSize != 0 {
    panic("decrypted is not a multiple of blowfish.BlockSize")
  }

  // create the decrypter
  dcbc := cipher.NewCBCDecrypter(dcipher, iv)

  // decrypt!
  dcbc.CryptBlocks(decrypted, decrypted)

  return decrypted, nil
}

// checksizeAndPad checks the size of the plaintext and pads it if necessary.
// Blowfish is a block cipher, thus the plaintext needs to be padded to
// a multiple of the algorithms blocksize (8 bytes).
// return the multiple-of-blowfish.BlockSize-sized plaintext
func checksizeAndPad(plaintext []byte) []byte {

  // calculate modulus of plaintext to blowfish's cipher block size
  // if result is not 0, then we need to pad

  modulus := len(plaintext) % blowfish.BlockSize
  if modulus != 0 {
    // calc bytes we need to pad to make plaintext a multiple of block size
    padlen := blowfish.BlockSize - modulus

    // add required padding
    for i := 0; i < padlen; i++ {
      plaintext = append(plaintext, 0)
    }
  }

  return plaintext
}
