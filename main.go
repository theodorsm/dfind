package main

import (
	"fmt"

	"github.com/google/gopacket"

	"log"
	"os"

	"github.com/google/gopacket/pcap"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Please provide a pcap file to read")
		os.Exit(1)
	}

	handle, err := pcap.OpenOffline(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {

		dtls := packet.ApplicationLayer().LayerContents()

		// DTLS v1.2
		// magic := []byte{0x16, 0xFE, 0xFD}
		// contentType := 0x0
		majorVersion := 0x1
		minorVersion := 0x2
		handshakeType := 0xd

		fmt.Printf("DTLS v%d.%d\n", 0xff-dtls[majorVersion], 0xff-dtls[minorVersion])

		switch dtls[handshakeType] {
		case 0x1:
			fmt.Println("Client Hello:")
		case 0x2:
			fmt.Println("Server Hello:")
		default:
			fmt.Println("Other handshake type:")
		}

		fmt.Printf("%x\n", dtls[handshakeType:])
	}
}
