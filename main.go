package main

// NOTE: Used this trick to get setup to work:
//       https://stackoverflow.com/questions/65748509/vscode-show-me-the-error-after-i-install-the-proxy-in-vscode

import (
	"fmt"
	"net"
)

func main() {
	// Set up channels to be used
	var (
		authReqChan chan AuthReq   = make(chan AuthReq, 1000)
		signupChan  chan SignupReq = make(chan SignupReq, 1000)
		scanChan    chan Scan      = make(chan Scan, 1000)
	// sd_channel     chan Sd_Msg     = make(chan Sd_Msg, 1000)
	// dd_channel     chan Dd_Msg     = make(chan Dd_Msg, 1000)
	// alert_channel  chan Alert_Msg  = make(chan Alert_Msg, 1000)
	// ack_channel    chan Ack_Msg    = make(chan Ack_Msg, 1000)
	)

	service := ":1200"
	tcpaddr, err := net.ResolveTCPAddr("tcp", service)
	checkErrorKill(err)
	fmt.Println("DEBUG:", tcpaddr.Network())

	// Create ONE listener which listens for incoming handshakes
	listener, err := net.ListenTCP(tcpaddr.Network(), tcpaddr)
	checkErrorKill(err)

	// Fork processor task
	go processor(signupChan, authReqChan, scanChan)

	// Fork scan task which simulates scanning the code of a device

	var i uint32 = 0

	for {
		c, err := listener.AcceptTCP()
		if !checkSuccessString("main.go, listener", err) {
			continue
		}
		go connHandler(c, i, signupChan, authReqChan)
		fmt.Println("INFO: New TCP connection from", c.RemoteAddr().String())

		i += 1
	}
}
