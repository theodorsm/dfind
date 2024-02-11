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

		contentType := 0x0
		handshakeType := 0xd
		length := 0xe
		fragmentOffset := 0x13
		majorVersion := 0x19
		minorVersion := 0x1a
		sessionLength := 0x3b
		// cookieLength := 0x3c

		// Check if handshake record
		if dtls[contentType] == 22 {

			switch dtls[handshakeType] {
			case 0x1:
				fmt.Println("=============")
				fmt.Println("Client Hello:")

				handshakeLength := uint(dtls[length+2]) | uint(dtls[length+1])<<8 | uint(dtls[length])<<16
				fmt.Printf("Length: %d\n", handshakeLength)

				fmt.Printf("Fragment Offset: %d\n", uint(dtls[fragmentOffset])|uint(dtls[fragmentOffset+1])<<8|uint(dtls[fragmentOffset+2])<<16)

				fmt.Printf("DTLS v%d.%d\n", 0xff-dtls[majorVersion], 0xff-dtls[minorVersion])

				cookieLength := sessionLength + int(dtls[sessionLength]) + 1
				cipherLength := cookieLength + int(dtls[cookieLength]) + 1
				cipherLengthValue := uint(dtls[cipherLength+1]) | uint(dtls[cipherLength])<<8
				fmt.Printf("Cipher suite length: %d\n", cipherLengthValue)

				ciphers := dtls[cipherLength+2 : cipherLength+2+int(cipherLengthValue)]
				fmt.Printf("Ciphers: %x\n", ciphers)

				compressionLength := cipherLength + 2 + int(cipherLengthValue) + 1
				extensionLength := compressionLength + int(dtls[compressionLength]) + 1
				extensionLengthValue := uint(dtls[extensionLength+1]) | uint(dtls[extensionLength])<<8
				fmt.Printf("Extension length: %d\n", extensionLengthValue)

				extensions := dtls[extensionLength+2 : extensionLength+2+int(extensionLengthValue)]
				fmt.Printf("Extensions: %x\n", extensions)
			case 0x2:
				fmt.Println("=============")
				fmt.Println("Server Hello:")

				handshakeLength := uint(dtls[length+2]) | uint(dtls[length+1])<<8 | uint(dtls[length])<<16
				fmt.Printf("Length: %d\n", handshakeLength)

				fmt.Printf("Fragment Offset: %d\n", uint(dtls[fragmentOffset])|uint(dtls[fragmentOffset+1])<<8|uint(dtls[fragmentOffset+2])<<16)

				fmt.Printf("DTLS v%d.%d\n", 0xff-dtls[majorVersion], 0xff-dtls[minorVersion])

				ciphersOffset := sessionLength + int(dtls[sessionLength]) + 1
				fmt.Printf("Chosen cipher suite: %x\n", dtls[ciphersOffset:ciphersOffset+2])
				extensionLength := ciphersOffset + 3
				extensionLengthValue := uint(dtls[extensionLength+1]) | uint(dtls[extensionLength])<<8
				fmt.Printf("Extension length: %d\n", extensionLengthValue)

				extensions := dtls[extensionLength+2 : extensionLength+2+int(extensionLengthValue)]
				fmt.Printf("Extensions: %x\n", extensions)
			default:
				fmt.Println("=============")
				fmt.Println("Other handshake type:")
				fmt.Printf("%x\n", dtls[handshakeType:])
			}

		}
	}
}
