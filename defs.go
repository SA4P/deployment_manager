package main

import (
	"fmt"
	"net"
	"time"
)

// ---------------------------------------------------------------------------------
//                                  Consts
// ---------------------------------------------------------------------------------

// Low-level lengths
const (
	SHA256_INPUT_SIZE  = 64 // 512 bits
	SHA256_OUTPUT_SIZE = 32 // 256 bits

	HMAC_INPUT_SIZE  = SHA256_INPUT_SIZE
	HMAC_KEY_LEN     = 32
	KEY_LEN          = HMAC_KEY_LEN
	HMAC_OUTPUT_SIZE = SHA256_OUTPUT_SIZE

	MAX_PAYLOAD_LEN = 256

	DEVICE_ID_LEN   = 4
	REB_CNT_LEN     = 4
	REQ_CNT_LEN     = 4
	ACCESS_TYPE_LEN = 2
	CHALLENGE_LEN   = 16
	RANDOM_LEN      = 16
)

// Header constants
const (
	HEADER_LEN      = 3
	HEADER_TYPE_LEN = 1
	HEADER_LEN_LEN  = 2
)

// Payload types
const (
	PAYLOAD_SIGNUP_REQ = iota
	PAYLOAD_SIGNUP_RESP
	PAYLOAD_AUTH_REQ
	PAYLOAD_AUTH_RESP
	PAYLOAD_CONTROL
)

// Payload lengths. NOTE: They are DIFFERENT to the ones between gateway and server
const (
	LEN_PAYLOAD_SIGNUP_REQ  = 2 + KEY_LEN + KEY_LEN + HMAC_OUTPUT_SIZE                                       // LOWER BOUND, 2 bytes device type
	LEN_PAYLOAD_SIGNUP_RESP = 4 + KEY_LEN + HMAC_OUTPUT_SIZE                                                 // NOTE: This is only for SENDing!
	LEN_PAYLOAD_AUTH_REQ    = DEVICE_ID_LEN + REB_CNT_LEN + REQ_CNT_LEN + ACCESS_TYPE_LEN + HMAC_OUTPUT_SIZE // Authentication request payload is: |  dev_id  |  req_cnt  |  req_cnt  |  access_type  |  hmac_tag  |
	LEN_PAYLOAD_AUTH_RESP   = RANDOM_LEN + HMAC_OUTPUT_SIZE
	LEN_PAYLOAD_CONTROL     = 3 // FIXME: Set correct LEN_CONTROL
)

var PAYLOAD_LENS []uint16 = []uint16{LEN_PAYLOAD_SIGNUP_REQ, LEN_PAYLOAD_SIGNUP_RESP, LEN_PAYLOAD_AUTH_REQ, LEN_PAYLOAD_AUTH_RESP, LEN_PAYLOAD_CONTROL}

// Access types
const (
	SAMPLE_SENSOR_0    = 0
	SAMPLE_SENSOR_1    = 1
	CONTROL_ACTUATOR_0 = 2
	CONTROL_ACTUATOR_1 = 3
	DUMMY_REQUEST      = 0x69
)

// ---------------------------------------------------------------------------------
//                                  Typedefs
// ---------------------------------------------------------------------------------

type Header struct {
	PayloadType uint8
	PayloadLen  uint16
}

type SignupReq struct {
	Conn    *net.TCPConn
	DevType uint16
	SPubGW  [KEY_LEN]byte
	EPubGw  [KEY_LEN]byte
	MacTag  []byte
	CapURI  []byte
}

type AuthReq struct {
	DevId      uint32
	AccessType uint16
	RebCnt     uint32
	ReqCnt     uint32
	MacTag     []byte
	// rawChal    []byte
}

type Scan struct {
	SPubGW [KEY_LEN]byte
	Psk    [KEY_LEN]byte
}

type Sessionkeys struct {
	K_gw_s []byte // Session key gateway -> server
	K_s_gw []byte // Session key server -> gateway
}

type LogEntry struct {
	ArrivalTime time.Time
	DevId       uint32
	Paired      bool
	AuthReq     AuthReq
}

type RepairingState struct { // Used to allow re-pairing during normal operation
	scan     Scan
	sessKeys Sessionkeys
}

type DeviceState struct {
	Conn           *net.TCPConn
	Id             uint32
	Type           uint16
	rebCnt         uint32 // Counter counting the reboots
	reqCnt         uint32 // Counter counting the number of requests sent since last reboot
	CapURI         string
	LastRandomness []byte
	Sesskeys       Sessionkeys
	Paired         bool
	ScanData       Scan
	Log            []LogEntry
}

type ServerState map[uint32]DeviceState

type Scans map[[32]byte]Scan

// ---------------------------------------------------------------------------------
//                                  Errors
// ---------------------------------------------------------------------------------

// Cryptographic Operation failed Error

// Invalid payload type error
type InvalidPayloadType struct {
	HandlerId   uint32
	PayloadType uint8
}

func (e *InvalidPayloadType) Error() string {
	return fmt.Sprintf("conn_id = %d: Header with invalid type: %d", e.HandlerId, e.PayloadType)
}

// Invalid payload length error
type InvalidPayloadLen struct {
	HandlerId   uint32
	PayloadType uint8
	PayloadLen  uint16
}

func (e *InvalidPayloadLen) Error() string {
	payloadType := e.PayloadType
	expectedLen := PAYLOAD_LENS[payloadType]
	actualLen := e.PayloadLen
	return fmt.Sprintf("HandlerId = %d: Header with payload type: %d, expected payload length: %d but actual payload length: %d", e.HandlerId, payloadType, expectedLen, actualLen)
}

// Invalid access type error
type InvalidAccessType struct {
	HandlerId  uint32
	AccessType uint16
}

func (e *InvalidAccessType) Error() string {
	return fmt.Sprintf("HandlerId = %d: Payload with access type: %d", e.HandlerId, e.AccessType)
}

// Not yet implemented payload type
type NotYetImplementedPayloadType struct {
	HandlerId   uint32
	PayloadType uint8
}

func (e *NotYetImplementedPayloadType) Error() string {
	return fmt.Sprintf("HandlerId = %d: Payload with not yet payload type: %d", e.HandlerId, e.PayloadType)
}
