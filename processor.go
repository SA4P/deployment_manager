package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/pkg/profile"
)

// Actual processor, the hearth of the server

func processor(signupReqChan chan SignupReq, authReqChan chan AuthReq, scanChan chan Scan) {

	defer profile.Start(profile.ProfilePath(".")).Stop()

	var (
		nextDevId uint32 // Counter holding the newest unused device ID
		// firstDev  bool   // Flag to signal it being the first device to sign up ==> Home owner device, which is then notified subsequently
		err error // Error object

		authReq   AuthReq   // Object holding authenticaion requests
		signupReq SignupReq // Object holding one byte device type and then raw json data (SignupReq is a byte slice)
		scan      Scan
		scans     Scans       = make(Scans)
		sState    ServerState = make(ServerState) // Server state
	)

	// DEBUG: Console task to poke the server
	go consoleTask(&sState, scanChan)
	// Infinite event loop
	for {
		select {

		case scan = <-scanChan:

			// (1) Extract static public key from scan and check if it already exists
			sPubGw := scan.SPubGW
			_, scanExists := scans[sPubGw]

			if scanExists {
				// Case: Scanned key which already existed previously ==> Ignore
				continue
			}

			// If we reached here, we know that the public key we received is fresh

			// (2) Add scan to map of scans
			scans[sPubGw] = scan

		case signupReq = <-signupReqChan:

			// TODO: Implement this block which sets the first device up as a home owner device
			// // First device ==> Always a home owner device
			// if firstDev {

			// }

			// (1) Perform the cryptographic handshake

			// (1.1) Check if scan corresponding to the included key exists
			sPubGw := signupReq.SPubGW

			scan, scanExists := scans[sPubGw]
			if !scanExists {
				// Case: Scan does NOT exist ==> Possible problem, possibly signup request without previously scanned key

				// (1.1.1) Check if key has been scanned but not processed:
				breakFlag := false
				for {
					select {
					case scan = <-scanChan:
						// (1.1.1.1) Extract static public key from scan and check if it already exists
						sPubGw := scan.SPubGW
						scan, scanExists := scans[sPubGw]

						if scanExists {
							// Case: Scanned key which already existed previously ==> Ignore
							continue
						}

						// If we reached here, we know that the public key we received is fresh

						// (1.1.1.2) Add scan to map of scans
						scans[sPubGw] = scan
					default:
						breakFlag = true
					}
					if breakFlag {
						break
					}
				}

				scan, scanExists = scans[sPubGw]
				if !scanExists {
					continue
				}
			}

			// If we reached here, we know that the Scan corresponding to the signup request's public key is store in scan

			// (1.2) Create local X25519 ephemeral keypair
			xSlice, xP, err := createEphemeralKeyPair()

			// If we reached here, we have successfully created an ephemeral keypair!

			// (1.3) Perform Diffie-Hellman on the keypairs

			var x [KEY_LEN]byte

			copy(x[:], xSlice)

			if !checkSuccessString("signupRequest, Handshake, create Eph. keypair:", err) {
				continue
			}

			ePubGw := signupReq.EPubGw

			// - - - - - - - - - - - - - - - - - -

			s1, err := diffieHellman(x, sPubGw)

			if !checkSuccessString("signupRequest, Handshake diffieHellman of s1:", err) {
				continue
			}

			s2, err := diffieHellman(x, ePubGw)
			if !checkSuccessString("signupRequest, Handshake diffieHellman of s2:", err) {
				continue
			}

			// (1.4) Derive two keys, one for gw->server authentication and one for server->gw authentication
			ikm := append(append(s1[:], s2[:]...), scan.Psk[:]...)

			var salt [16]byte

			infos := make([][]byte, 2)

			infos[0] = []byte("gw_s")
			infos[1] = []byte("s_gw")

			keys := Hkdf(ikm, salt, infos)

			sessKeys := Sessionkeys{K_gw_s: keys[0], K_s_gw: keys[1]}

			// If we reached here, we have successfully LOCALLY established the keys.
			// We still need confirmation that the gateway has derived the same keys, thus the pairing flag of the DeviceState to be created is set to FALSE

			// - - - - - - - - - - - - - - - - - -

			// (2) Extract the device type
			devType := signupReq.DevType

			// (3) Add device to state
			// (3.1) Create empty log
			log := make([]LogEntry, 0)

			// (3.2) Get device ID and increment the global counter
			devId := nextDevId
			nextDevId += 1

			// (3.3) Set state
			sState[devId] = DeviceState{ // TODO: Add Pubkey
				Conn:           signupReq.Conn,
				Id:             devId,
				Type:           devType,
				rebCnt:         0,
				reqCnt:         0,
				LastRandomness: make([]byte, RANDOM_LEN),
				CapURI:         string(signupReq.CapURI),
				Sesskeys:       sessKeys,
				Paired:         false,
				ScanData:       scan,
				Log:            log,
			}

			fmt.Println("DEBUG: Received signupReq:", signupReq)
			fmt.Println("DEBUG: Device capability URI:", string(signupReq.CapURI))
			fmt.Println("DEBUG: Assigned device ID:", devId)

			fmt.Println("-------------------------------------")
			fmt.Printf("%+v\n", sState[devId])
			fmt.Println("-------------------------------------")

			// (4) Send signup response

			//	   Recall, the signup response here has structure:
			//	   | Header (3 bytes) | DeviceId (4 bytes) | xP (32 bytes) | HMAC(PSK, xP || ePubGW) (32 bytes) |

			respMsg, err := createSignupResp(devId, xP, ePubGw[:], scan.Psk[:])
			if !checkSuccessString("signupRequest, Handshake, creating Signup Response", err) {
				continue
			}

			// (5.3) Send signup response
			_, err = signupReq.Conn.Write(respMsg)
			checkSuccessString("signupRequest, Handshake, sending Signup Response", err)
		case authReq = <-authReqChan:

			fmt.Println("DEBUG: Received autReq:", authReq)

			var devId uint32 = authReq.DevId

			// (1) Check if device ID exists
			devState, exists := sState[devId]
			if !exists {
				continue
			}

			// (2) Append to log

			//(2.1) Create new log entry
			logEntry := LogEntry{ArrivalTime: time.Now(), Paired: devState.Paired, AuthReq: authReq}

			// (2.2) Append log entry to the log
			devState.Log = append(devState.Log, logEntry)

			//FIXME: This is inefficient, it would be better to just have a map to REFERENCES of device states!

			// (2.3) Write back log
			sState[devId] = devState

			// (3) Check request for freshness and authenticity
			// (3.1) Get Server->Gateway key
			chalKey := devState.Sesskeys.K_gw_s
			authKey := devState.Sesskeys.K_s_gw

			// (3.2) Create HMAC functor to check the request
			chalHmacer := hmac.New(sha256.New, chalKey)

			// (3.3) Check if challenge is fresh and authentic

			// (3.3.1) Check if counters are at least as large as current counters. This creates a sidechannel where attacker can learn expected counter value
			if authReq.RebCnt < devState.rebCnt {
				// CASE: Request before a previous reboot of the gateway ==> old request
				fmt.Println("WARNING, processor, authReq: Authentication Request has old rebCnt")
				continue
			}

			if authReq.ReqCnt < devState.reqCnt {
				// CASE: Request's boot counter is fresh but request counter is less than the server's counter ==> old request
				fmt.Println("WARNING, processor, authReq: Authentication Request has old reqCnt")

				continue
			}

			// (3.3.2) Create slice to MAC over
			macInput := make([]byte, REB_CNT_LEN+REQ_CNT_LEN+ACCESS_TYPE_LEN+RANDOM_LEN)
			// WARNING: If REB_CNT_LEN != 4, the following fails because it copies 32 bits (4 bytes)!
			binary.LittleEndian.PutUint32(macInput, authReq.RebCnt)
			binary.LittleEndian.PutUint32(macInput[REB_CNT_LEN:], authReq.ReqCnt)
			binary.LittleEndian.PutUint16(macInput[REB_CNT_LEN+REQ_CNT_LEN:], authReq.AccessType)
			copy(macInput[REB_CNT_LEN+REQ_CNT_LEN+ACCESS_TYPE_LEN:], devState.LastRandomness)

			// (3.3.3) Check MAC-tag
			_, err = chalHmacer.Write(macInput)
			if !checkSuccessString("processor, authReq, chalHmac digesting message", err) {
				continue
			}

			// (3.3.4) Compute digest
			macTag := chalHmacer.Sum(nil)

			// (3.3.5) Compare with included tag
			macEquals := subtle.ConstantTimeCompare(macTag, authReq.MacTag)
			if macEquals != 1 {
				// 1§ : MAC Tags disagree
				fmt.Println("WARNING, processor, authReq: Authentication Request has bad MAC Tag")
				continue
			}

			// If we reach here, the request is fresh and authentic

			// NOTE: If the device had not been paired previously, we here set the flag as paired because the device has proven that it knows the key,
			//		 so we know the device is fully paired!

			if authReq.AccessType == DUMMY_REQUEST {
				// NOTE: The DUMMY_REQUEST does NOT change the randomness field stored in the device state.
				//       That is because no response (holding randomness) is ever created by the server!
				devState.Paired = true
				fmt.Println("DEBUG, processor, authReq: Received authentic pairing dummy message ==> Now (re)paired")
				continue
			}

			fmt.Println("DEBUG, processor, authReq: Received fresh and authentic authentication request from device:", devId)

			// (4) Create authentic response

			// (4.2) Create slice to MAC over. It holds:
			//		 |  sRandom  |  authReq.macTag  |
			respSlice := make([]byte, RANDOM_LEN+HMAC_OUTPUT_SIZE)
			_, err := rand.Read(respSlice[:RANDOM_LEN])
			if !checkSuccessString("processor, authReq, randomness generation", err) {
				continue
			}
			copy(respSlice[RANDOM_LEN:], authReq.MacTag)

			// CHANGE: Moved this down
			// (4.3) Update the server's counters AND LastRandomness and write changes back to server State sState
			devState.rebCnt = authReq.RebCnt
			devState.reqCnt = authReq.ReqCnt
			devState.LastRandomness = respSlice[:RANDOM_LEN]
			sState[devId] = devState

			// (4.4) Create authentication MAC tag over respSlice
			authHmacer := hmac.New(sha256.New, authKey)

			_, err = authHmacer.Write(respSlice)
			if !checkSuccessString("processor, authReq, authHmac digesting message", err) {
				continue
			}

			authTag := authHmacer.Sum(nil)

			// (4.5) Create final response payload.
			//		 We take the current respSlice:              |  sRandom  |  authReq.macTag  |
			//		 and overwrite the old with the new MAC-Tag: |  sRandom  |     authTag      |
			copy(respSlice[RANDOM_LEN:], authTag)

			// (5) Send response
			// (5.1) Allocate message buffer, populate it to hold: |  header  |  sRandom  |  authTag  |
			authMsg := make([]byte, HEADER_LEN+LEN_PAYLOAD_AUTH_RESP)
			buildMsg(authMsg, PAYLOAD_AUTH_RESP, respSlice)

			// (5.2) Send message over connection
			n, err := devState.Conn.Write(authMsg)
			if !checkSuccessString("processor, authReq, sending message", err) {
				// If partial message was sent, print what was sent
				fmt.Println("ERROR /2: n =", n, "bytes were written, which means message: \""+hex.EncodeToString(authMsg[:n])+"\"")
			}
		}
	}
}
