package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"

	"golang.org/x/crypto/curve25519"
)

func checkErrorKill(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error: %s", err.Error())
		os.Exit(1)
	}
}

func checkSuccessString(msg string, err error) bool {
	if err == nil {
		return true
	}

	fmt.Println("ERROR,", msg+": Error content:", err.Error())
	return false
}

func initSlice(s []byte, b byte) {
	for i := range s {
		s[i] = b
	}
}

func buildHeader(headerBuf []byte, payloadType uint8) {
	headerBuf[0] = payloadType
	binary.LittleEndian.PutUint16(headerBuf[1:3], PAYLOAD_LENS[payloadType])
}

func buildMsg(outBuf []byte, payloadType uint8, payload []byte) {
	buildHeader(outBuf, payloadType)
	copy(outBuf[HEADER_LEN:], payload)
}

// func spinInfinite(msg string) {
// 	for {
// 		fmt.Println("ERROR, infinite loop:", msg)
// 		time.Sleep(1 * time.Second)
// 	}
// }

// Parameter index is the position in the log, starting at 0
func (e *LogEntry) prettyPrint(index int) {
	accessType := e.AuthReq.AccessType
	arrivalTime := e.ArrivalTime
	devId := e.DevId

	fmt.Printf("Device ID: %v, Index: %v, Access Type: %v, Arrival time: %v\n", devId, index, accessType, arrivalTime)
}

func createEphemeralKeyPair() ([]byte, []byte, error) {
	// (0.2.1) Create private key x

	var err error

	x := make([]byte, 32)
	nBytes, err := rand.Reader.Read(x)
	if err != nil {
		return nil, nil, err
	}

	fmt.Println("DEBUG, signupRequest, Ephemeral Key Generation: Private key has n =", nBytes, "bytes.")

	// (0.2.2) Create public key y
	y, err := curve25519.X25519(x, curve25519.Basepoint)

	return x, y, err
}

// Diffie-Hellman. priv is a scalar, pub is a point
func diffieHellman(priv [KEY_LEN]byte, pub [KEY_LEN]byte) ([]byte, error) {

	secret, err := curve25519.X25519(priv[:], pub[:])

	return secret, err
}

func HkdfExtract(salt [16]byte, ikm []byte) []byte {

	hmacer := hmac.New(sha256.New, salt[:])

	hmacer.Write(ikm)
	prk := hmacer.Sum(nil)

	return prk
}

func HkdfExpandSimplified(prk []byte, info []byte) []byte {
	// (1) Compute input for T(1) in RFC 5869, for that we take the info string and concatenate 0x01 to it
	hmacInput := append(info, byte(0x01))

	hmacer := hmac.New(sha256.New, prk)

	hmacer.Write(hmacInput)
	secret := hmacer.Sum(nil)

	return secret

}

func Hkdf(ikm []byte, salt [16]byte, infos [][]byte) [][]byte {

	prk := HkdfExtract(salt, ikm)

	keys := make([][]byte, len(infos)) // Allocate slice of slices, which holds one slice for each key to be generated (one key per info string)

	for index, info := range infos {
		keys[index] = HkdfExpandSimplified(prk, info)
	}

	return keys
}

func createSignupResp(devId uint32, ePubSRV []byte, ePubGW []byte, psk []byte) ([]byte, error) {

	// (1) Allocate message buffer
	msgBuf := make([]byte, HEADER_LEN+LEN_PAYLOAD_SIGNUP_RESP)

	// (2) Build header
	buildHeader(msgBuf[0:3], PAYLOAD_SIGNUP_RESP)

	// (3) Populate payload with: | devId (4 bytes) | ePubSRV (KEY_LEN == 32 bytes) | HMAC(psk, ePubSRV || ePubGW) |

	payloadBuf := msgBuf[3:]

	// (3.1) Write device ID into payload buffer
	binary.LittleEndian.PutUint32(payloadBuf, devId)

	// (3.1) Write ePubSRV into payload buffer
	copy(payloadBuf[DEVICE_ID_LEN:], ePubSRV)

	// (3.2) Compute MAC tag
	hmacer := hmac.New(sha256.New, psk)
	hmacInput := append(ePubSRV, ePubGW...)
	_, err := hmacer.Write(hmacInput)
	if err != nil {
		return nil, err
	}
	macTag := hmacer.Sum(nil)

	// (3.3) Write MAC tag into payload buffer
	copy(payloadBuf[DEVICE_ID_LEN+KEY_LEN:], macTag)

	return msgBuf, nil
}
