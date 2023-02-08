// Worker process serving a single TCP connection
package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
)

func connHandler(c *net.TCPConn, handlerId uint32, signupReqChan chan SignupReq, authReqChan chan AuthReq) {
	var err error

	// Debugging variable, used in checkSuccessString and similar
	handlerIdString := "tcpHandler, handlerId: " + strconv.Itoa(int(handlerId))

	// Buffers used to receive messages
	headerBuf := make([]byte, 3)

	// Payload type and payload length
	var (
		payloadType uint8
		payloadLen  uint16
	)

	for {

		// (1) Read header
		_, err = io.ReadFull(c, headerBuf)
		if checkConnClosed(err) { // Check if EOF was read ==>
			break
		}
		if !checkSuccessString(handlerIdString, err) { // Check for any other error
			continue
		}

		// (2) Parse header
		header, err := parseHeader(headerBuf, handlerId)
		if !checkSuccessString(handlerIdString, err) {
			continue
		}

		payloadType = header.PayloadType
		payloadLen = header.PayloadLen

		// (3) Read payload from TCP connection, i.e. payloadLen many bytes
		payloadBuf := make([]byte, payloadLen)

		_, err = io.ReadFull(c, payloadBuf)
		if checkConnClosed(err) {
			fmt.Println("WARNING,", handlerIdString, "Reading payload gave an EOF or UnexpectedEOF error ==> Connection closed while (not after) receiving a payload. Likely and error...")
			break
		}

		fmt.Println("DEBUG:", handlerIdString+": Received header:", headerBuf, "\nand payload:", payloadBuf)

		if !checkSuccessString(handlerIdString, err) {
			continue
		}

		// (4) Process payload (includes sending it to correct channel)
		err = processPayload(payloadBuf, payloadType, c, signupReqChan, authReqChan, handlerId, handlerIdString)
		checkSuccessString(handlerIdString, err)

	}

	fmt.Println("INFO:", handlerIdString, "read EOF or UnexpectedEOF ==> Exited for-loop and will terminate now")
}

func checkConnClosed(err error) bool {
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return true
	}

	return false
}

func parseHeader(headerBuf []byte, handlerId uint32) (Header, error) {

	// (1) Extract and check payload type

	// (1.1) Extract payload type
	var payloadType uint8 = headerBuf[0]

	// (1.2) Check if payload type is expected. Note that we have only two inbound expected types: SIGNUP_REQ and AUTH_REQ. Any other value is either for outbound messages or just invalid
	if (payloadType != PAYLOAD_AUTH_REQ) && (payloadType != PAYLOAD_SIGNUP_REQ) {
		return Header{}, &InvalidPayloadType{HandlerId: handlerId, PayloadType: headerBuf[0]}
	}

	// (2) Extract and check payload length

	// (2.1) Extract payload length
	var payloadLen uint16 = binary.LittleEndian.Uint16(headerBuf[1:])

	// (2.2) Check payload length given payload type
	// TODO: Change this such that PAYLOAD_SIGNUP is handled in a more graceful way
	if payloadType != PAYLOAD_SIGNUP_REQ && payloadLen != PAYLOAD_LENS[payloadType] {
		return Header{}, &InvalidPayloadLen{HandlerId: handlerId, PayloadType: payloadType, PayloadLen: payloadLen}
	}

	// (3) Return Header VALUE (==> No pointer) and no error (==> nil pointer)
	return Header{PayloadType: payloadType, PayloadLen: payloadLen}, nil

}

// Parses the payload AND sends it to corresponding channel
func processPayload(payloadBuf []byte, payloadType uint8, conn *net.TCPConn, signupReqChan chan SignupReq, authReqChan chan AuthReq, handlerId uint32, handlerIdString string) error {
	switch payloadType {
	case PAYLOAD_SIGNUP_REQ:

		var sPub [KEY_LEN]byte
		copy(sPub[:], payloadBuf[2:2+KEY_LEN])

		var ePub [KEY_LEN]byte
		copy(ePub[:], payloadBuf[2+KEY_LEN:2+KEY_LEN+KEY_LEN])
		macTag := payloadBuf[2+KEY_LEN+KEY_LEN : 2+KEY_LEN+KEY_LEN+HMAC_OUTPUT_SIZE]
		capURI := payloadBuf[2+KEY_LEN+KEY_LEN+HMAC_OUTPUT_SIZE:]

		signupReq := SignupReq{Conn: conn, DevType: binary.LittleEndian.Uint16(payloadBuf[0:2]), SPubGW: sPub, EPubGw: ePub, MacTag: macTag, CapURI: capURI}

		signupReqChan <- signupReq
		return nil
	case PAYLOAD_AUTH_REQ:
		fmt.Println("DEBUG, parsePayload of ", handlerIdString+": Received authentication request")

		// Parse authentication request
		authReq, err := parseAuthReq(payloadBuf, handlerId)
		if err != nil { // If an error occurred, bubble it up
			return err
		}
		authReqChan <- authReq // Enqueue valid authentication request into its channel to then be processed by the processor task
		return nil
	default:
		return &NotYetImplementedPayloadType{HandlerId: handlerId, PayloadType: payloadType}
	}
}

// Extract device ID, access type and challenge and returns a corresponding struct
func parseAuthReq(payloadBuf []byte, handlerId uint32) (AuthReq, error) {

	var (
		deviceId   uint32 = binary.LittleEndian.Uint32(payloadBuf)
		rebCnt     uint32 = binary.LittleEndian.Uint32(payloadBuf[DEVICE_ID_LEN:])
		reqCnt     uint32 = binary.LittleEndian.Uint32(payloadBuf[DEVICE_ID_LEN+REB_CNT_LEN:])
		accessType uint16 = binary.LittleEndian.Uint16(payloadBuf[DEVICE_ID_LEN+REB_CNT_LEN+REQ_CNT_LEN:])
		macTag     []byte = payloadBuf[DEVICE_ID_LEN+REB_CNT_LEN+REQ_CNT_LEN+ACCESS_TYPE_LEN:]
	)

	if (accessType < SAMPLE_SENSOR_0 || accessType > CONTROL_ACTUATOR_1) && accessType != DUMMY_REQUEST {
		return AuthReq{}, &InvalidAccessType{HandlerId: handlerId, AccessType: accessType}
	}

	return AuthReq{DevId: deviceId, AccessType: accessType, RebCnt: rebCnt, ReqCnt: reqCnt, MacTag: macTag}, nil
}
