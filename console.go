package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func consoleTask(sState *ServerState, scanChan chan Scan) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("CONSOLE: Console task started")
	fmt.Println("CONSOLE: ---------------------")

	// TODO: Remove those lines, including the fmt.Println("CONSOLE: Scan received successfully")!
	var pubKeyArray [KEY_LEN]byte // Do this such that we can store fixed-length arrays in the scan object
	pubKey, _ := hex.DecodeString("50d2813e7611fe0177421385e193de017f2259a25c278645e3ed74f723808370")
	copy(pubKeyArray[:], pubKey)

	var pskArray [KEY_LEN]byte // Do this such that we can store fixed-length arrays in the scan object
	psk, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	copy(pskArray[:], psk)
	fmt.Println("CONSOLE: Scan received successfully")

	scanChan <- Scan{SPubGW: pubKeyArray, Psk: pskArray}

	for {
		resp, _ := reader.ReadString('\n')

		resp = resp[:len(resp)-1]

		slicedResp := strings.Split(resp, " ")

		command := slicedResp[0]

		if strings.Contains(command, "log") {
			if len(slicedResp) != 2 {
				fmt.Printf("CONSOLE, Error: Entered command \"log\" has unexpected number of parameters (%v instead of expected 1)\n", len(slicedResp))
				continue
			}
			devId, err := strconv.Atoi(slicedResp[1])

			if !checkSuccessString("CONSOLE", err) {
				continue
			}

			devState, devExists := (*sState)[uint32(devId)]

			if !devExists {
				fmt.Printf("CONSOLE, Warning: Device ID %v not found in Server State!\n", devId)
				continue
			}

			logSlice := devState.Log

			fmt.Printf("CONSOLE: - - - - - LOG entries for device ID: %v - - - - -\n", devId)

			for i, entry := range logSlice {
				entry.prettyPrint(i)
			}
		} else if strings.Contains(command, "scan") {

			if len(slicedResp) != 3 {
				fmt.Printf("CONSOLE, Error: Entered command \"scan\" has unexpected number of parameters (%v instead of expected 2)\n", len(slicedResp))
				continue
			}

			pubKey, err := hex.DecodeString(slicedResp[1])
			if !checkSuccessString("SCAN pubKey", err) {
				continue
			}

			var pubKeyArray [KEY_LEN]byte // Do this such that we can store fixed-length arrays in the scan object
			copy(pubKeyArray[:], pubKey)

			psk, err := hex.DecodeString(slicedResp[2])
			if !checkSuccessString("SCAN psk", err) {
				continue
			}

			var pskArray [KEY_LEN]byte
			copy(pskArray[:], psk)

			// fmt.Printf("DEBUG, console: Scanned following data: %x", Scan{Psk: pskArray, SPubGW: pubKeyArray})

			scanChan <- Scan{Psk: pskArray, SPubGW: pubKeyArray}
			fmt.Println("CONSOLE: Scan received successfully")
		} else {
			fmt.Printf("CONSOLE: Command %s unknown\n", command)
		}
	}

}
