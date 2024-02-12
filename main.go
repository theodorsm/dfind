package main

import (
	"encoding/hex"
	"fmt"

	"github.com/google/gopacket"

	"log"
	"os"

	"github.com/google/gopacket/pcap"

	"database/sql"

	"github.com/go-sql-driver/mysql"
)

type Fingerprint struct {
	HandshakeType   uint
	Length          uint
	FragmentOffset  uint
	MajorVersion    byte
	MinorVersion    byte
	CipherLength    uint
	Ciphers         []byte
	ChosenCipher    []byte
	ExtensionLength uint
	Extensions      []byte
}

const OffsetContentType = 0x0
const OffsetHandshakeType = 0xd
const OffsetLength = 0xe
const OffsetFragmentOffset = 0x13
const OffsetMajorVersion = 0x19
const OffsetMinorVersion = 0x1a
const OffsetSessionLength = 0x3b

func addFingerprint(db *sql.DB, fp Fingerprint) error {
	result, err := db.Exec("INSERT INTO fingerprint (type, handshakeType, length, fragmentOffset, majorVersion, minorVersion, cipherLength, ciphers, chosenCipher, extensionLength, extensions) VALUES ('snowflake', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", fp.HandshakeType, fp.Length, fp.FragmentOffset, int(fp.MajorVersion), int(fp.MinorVersion), fp.CipherLength, hex.EncodeToString(fp.Ciphers), hex.EncodeToString(fp.ChosenCipher), fp.ExtensionLength, hex.EncodeToString(fp.Extensions))
	if err != nil {
		return fmt.Errorf("addFingerprint: %v", err)
	}
	id, err := result.LastInsertId()
	fmt.Printf("Fingerprint ID: %d\n", id)
	if err != nil {
		return fmt.Errorf("addFingerprint: %v", err)
	}
	return nil
}

func main() {

	cfg := mysql.Config{
		User:                 os.Getenv("DBUSER"),
		Passwd:               os.Getenv("DBPASS"),
		Net:                  "tcp",
		Addr:                 "127.0.0.1:3306",
		DBName:               "dtls_fingerprinting",
		AllowNativePasswords: true,
	}

	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	pingErr := db.Ping()
	if pingErr != nil {
		log.Fatal(pingErr)
	}
	fmt.Println("Connected to DB!")

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

		fp := Fingerprint{}

		// Check if handshake record
		if dtls[OffsetContentType] == 22 {

			fp.HandshakeType = uint(dtls[OffsetHandshakeType])

			switch fp.HandshakeType {
			case 0x1:
				fmt.Println("=============")
				fmt.Println("Client Hello:")

				fp.Length = uint(dtls[OffsetLength+2]) | uint(dtls[OffsetLength+1])<<8 | uint(dtls[OffsetLength])<<16
				fmt.Printf("Length: %d\n", fp.Length)

				fp.FragmentOffset = uint(dtls[OffsetFragmentOffset]) | uint(dtls[OffsetFragmentOffset+1])<<8 | uint(dtls[OffsetFragmentOffset+2])<<16
				fmt.Printf("Fragment Offset: %d\n", fp.FragmentOffset)

				fp.MajorVersion = dtls[OffsetMajorVersion]
				fp.MinorVersion = dtls[OffsetMinorVersion]
				fmt.Printf("DTLS v%d.%d\n", 0xff-fp.MajorVersion, 0xff-fp.MinorVersion)

				OffsetCookieLength := OffsetSessionLength + int(dtls[OffsetSessionLength]) + 1
				OffsetCipherLength := OffsetCookieLength + int(dtls[OffsetCookieLength]) + 1
				fp.CipherLength = uint(dtls[OffsetCipherLength+1]) | uint(dtls[OffsetCipherLength])<<8
				fmt.Printf("Cipher suite length: %d\n", fp.CipherLength)

				fp.Ciphers = dtls[OffsetCipherLength+2 : OffsetCipherLength+2+int(fp.CipherLength)]
				fmt.Printf("Ciphers: %x\n", fp.Ciphers)

				OffsetCompressionLength := OffsetCipherLength + 2 + int(fp.CipherLength) + 1
				OffsetExtensionLength := OffsetCompressionLength + int(dtls[OffsetCompressionLength]) + 1
				fp.ExtensionLength = uint(dtls[OffsetExtensionLength+1]) | uint(dtls[OffsetExtensionLength])<<8
				fmt.Printf("Extension length: %d\n", fp.ExtensionLength)

				fp.Extensions = dtls[OffsetExtensionLength+2 : OffsetExtensionLength+2+int(fp.ExtensionLength)]
				fmt.Printf("Extensions: %x\n", fp.Extensions)
				err := addFingerprint(db, fp)
				if err != nil {
					fmt.Println(err)
				}
			case 0x2:
				fmt.Println("=============")
				fmt.Println("Server Hello:")

				handshakeLength := uint(dtls[OffsetLength+2]) | uint(dtls[OffsetLength+1])<<8 | uint(dtls[OffsetLength])<<16
				fmt.Printf("Length: %d\n", handshakeLength)

				fmt.Printf("Fragment Offset: %d\n", uint(dtls[OffsetFragmentOffset])|uint(dtls[OffsetFragmentOffset+1])<<8|uint(dtls[OffsetFragmentOffset+2])<<16)

				fmt.Printf("DTLS v%d.%d\n", 0xff-dtls[OffsetMajorVersion], 0xff-dtls[OffsetMinorVersion])

				OffsetChosenCipher := OffsetSessionLength + int(dtls[OffsetSessionLength]) + 1
				fp.ChosenCipher = dtls[OffsetChosenCipher : OffsetChosenCipher+2]
				fmt.Printf("Chosen cipher suite: %x\n", fp.ChosenCipher)

				OffsetExtensionLength := OffsetChosenCipher + 3
				fp.ExtensionLength = uint(dtls[OffsetExtensionLength+1]) | uint(dtls[OffsetExtensionLength])<<8
				fmt.Printf("Extension length: %d\n", fp.ExtensionLength)

				fp.Extensions = dtls[OffsetExtensionLength+2 : OffsetExtensionLength+2+int(fp.ExtensionLength)]
				fmt.Printf("Extensions: %x\n", fp.Extensions)
				err := addFingerprint(db, fp)
				if err != nil {
					fmt.Println(err)
				}
			default:
				fmt.Println("=============")
				fmt.Println("Other handshake type:")
				fmt.Printf("%x\n", dtls[OffsetHandshakeType:])
			}

		}
	}
}
