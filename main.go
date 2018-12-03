package main

import (
  "fmt"
  "errors"
  "unicode/utf8"
)

var (
  constant = [4]uint32{0x61707865, 0x3320646e, 0x79622d32, 0x6b206574}
)

/**
 * Key: 256 bits = 32 bytes = 4 bytes * 8 -> [8]uint32
 * Nonce: 96bites = 12 bytes = 4 bytes * 3 -> [3]uint32
 *
 * Constant value will be embedded inside as the counter init as 1
 */
func NewState(key []uint32, nonce []uint32) (*[16]uint32, error) {
  if len(key) != 8 {
    return nil, errors.New(fmt.Sprintf("Illegal length of the key (%d != %d)", len(key), 8))
  }
  if len(nonce) != 3 {
    return nil, errors.New(fmt.Sprintf("Illegal length of the nonce (%d != %d)", len(nonce), 3))
  }
  var state [16]uint32
  for i := 0; i < 4; i++ {
    state[i] = constant[i]
  }

  for i:= 0; i < 8; i++ {
    state[i+4] = key[i]
  }

  state[12] = 0
  for i:=0; i < 3; i++ {
    state[i+13] = nonce[i]
  }

  return &state, nil
}

/**
 * Encode string to array of uint32, and return its slice
 * Don't call this: EncodeKey and EncodeNonce will call it with specific length.
 *
 * TODO: make it work first; so later in theory we should have a fixed length array version
 * with macro to fulfill the length and statically allocate memory.
 **/
func Encode(str string, length int) ([]uint32, error) {
  if len(str) != length {
    return nil, errors.New(fmt.Sprintf("Illegal length of strkey (%d !=%d)", len(str), length))
  }
  r := make([]uint32, length)
  for pos, char := range str {
    if utf8.RuneLen(char) > 1 {
      return nil, errors.New("Illegal width of character (>1)")
    }
    r[pos] = uint32(char)
  }
  return r, nil
}

func EncodeKey(strkey string) ([]uint32, error) {
  return Encode(strkey, 8)
}

func EncodeNonce(strkey string) ([]uint32, error) {
  return Encode(strkey, 3)
}

func main() {

  // Only byte-width: 1 can be accepted.
  const testkey = "01234567"
  const testnonce = "123"

  ek, ee := EncodeKey(testkey)
  if ee != nil {
    fmt.Print(ee)
    return
  }
  en, ee := EncodeNonce(testnonce)
  if ee != nil {
    fmt.Print(ee)
    return
  }
  er, ee := NewState(ek, en)
  if ee != nil {
    fmt.Print(ee)
    return
  }
  fmt.Print(er)
}
