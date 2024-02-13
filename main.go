package main

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-sql-driver/mysql"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
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

const ClientHelloType = 0x1
const ServerHelloType = 0x2

var fingerprintType string

var analyzeFields = []string{"cipherLength", "ciphers", "chosenCipher", "extensionLength", "extensions"}

func addFingerprint(db *sql.DB, filename string, fp Fingerprint) error {
	result, err := db.Exec("INSERT INTO fingerprint (type, filename, handshakeType, length, fragmentOffset, majorVersion, minorVersion, cipherLength, ciphers, chosenCipher, extensionLength, extensions) VALUES (?, ? , ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", fingerprintType, filename, fp.HandshakeType, fp.Length, fp.FragmentOffset, int(fp.MajorVersion), int(fp.MinorVersion), fp.CipherLength, hex.EncodeToString(fp.Ciphers), hex.EncodeToString(fp.ChosenCipher), fp.ExtensionLength, hex.EncodeToString(fp.Extensions))
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

func printFingerprint(fp Fingerprint) {
	fmt.Println("=============")
	switch fp.HandshakeType {
	case ClientHelloType:
		fmt.Println("Client Hello:")
		fmt.Printf("Length: %d\n", fp.Length)
		fmt.Printf("Fragment Offset: %d\n", fp.FragmentOffset)
		fmt.Printf("DTLS v%d.%d\n", 0xff-fp.MajorVersion, 0xff-fp.MinorVersion)
		fmt.Printf("Cipher suite length: %d\n", fp.CipherLength)
		fmt.Printf("Ciphers: %x\n", fp.Ciphers)
		fmt.Printf("Extension length: %d\n", fp.ExtensionLength)
		fmt.Printf("Extensions: %x\n", fp.Extensions)
	case ServerHelloType:
		fmt.Println("Server Hello:")
		fmt.Printf("Length: %d\n", fp.Length)
		fmt.Printf("Fragment Offset: %d\n", fp.FragmentOffset)
		fmt.Printf("DTLS v%d.%d\n", 0xff-fp.MajorVersion, 0xff-fp.MinorVersion)
		fmt.Printf("Chosen cipher suite: %x\n", fp.ChosenCipher)
		fmt.Printf("Extension length: %d\n", fp.ExtensionLength)
		fmt.Printf("Extensions: %x\n", fp.Extensions)
	default:
		return
	}
}

func parsePcap(db *sql.DB, path string, filename string) {
	handle, err := pcap.OpenOffline(path)
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
			case ClientHelloType:
				fp.Length = uint(dtls[OffsetLength+2]) | uint(dtls[OffsetLength+1])<<8 | uint(dtls[OffsetLength])<<16
				fp.FragmentOffset = uint(dtls[OffsetFragmentOffset+2]) | uint(dtls[OffsetFragmentOffset+1])<<8 | uint(dtls[OffsetFragmentOffset])<<16
				fragmentLength := uint(dtls[OffsetFragmentOffset+5]) | uint(dtls[OffsetFragmentOffset+4])<<8 | uint(dtls[OffsetFragmentOffset+3])<<16
				if fragmentLength != fp.Length {
					// TODO: parse fargemented records
					return
				}
				fp.MajorVersion = dtls[OffsetMajorVersion]
				fp.MinorVersion = dtls[OffsetMinorVersion]
				OffsetCookieLength := OffsetSessionLength + int(dtls[OffsetSessionLength]) + 1
				OffsetCipherLength := OffsetCookieLength + int(dtls[OffsetCookieLength]) + 1
				fp.CipherLength = uint(dtls[OffsetCipherLength+1]) | uint(dtls[OffsetCipherLength])<<8
				fp.Ciphers = dtls[OffsetCipherLength+2 : OffsetCipherLength+2+int(fp.CipherLength)]
				OffsetCompressionLength := OffsetCipherLength + 2 + int(fp.CipherLength) + 1
				OffsetExtensionLength := OffsetCompressionLength + int(dtls[OffsetCompressionLength]) + 1
				fp.ExtensionLength = uint(dtls[OffsetExtensionLength+1]) | uint(dtls[OffsetExtensionLength])<<8
				fp.Extensions = dtls[OffsetExtensionLength+2 : OffsetExtensionLength+2+int(fp.ExtensionLength)]
				printFingerprint(fp)
				err := addFingerprint(db, filename, fp)
				if err != nil {
					fmt.Println(err)
				}
			case ServerHelloType:
				fp.Length = uint(dtls[OffsetLength+2]) | uint(dtls[OffsetLength+1])<<8 | uint(dtls[OffsetLength])<<16
				fp.FragmentOffset = uint(dtls[OffsetFragmentOffset+2]) | uint(dtls[OffsetFragmentOffset+1])<<8 | uint(dtls[OffsetFragmentOffset])<<16
				fragmentLength := uint(dtls[OffsetFragmentOffset+5]) | uint(dtls[OffsetFragmentOffset+4])<<8 | uint(dtls[OffsetFragmentOffset+3])<<16
				if fragmentLength != fp.Length {
					return
				}
				fp.MajorVersion = dtls[OffsetMajorVersion]
				fp.MinorVersion = dtls[OffsetMinorVersion]
				OffsetChosenCipher := OffsetSessionLength + int(dtls[OffsetSessionLength]) + 1
				fp.ChosenCipher = dtls[OffsetChosenCipher : OffsetChosenCipher+2]
				OffsetExtensionLength := OffsetChosenCipher + 3
				fp.ExtensionLength = uint(dtls[OffsetExtensionLength+1]) | uint(dtls[OffsetExtensionLength])<<8
				fp.Extensions = dtls[OffsetExtensionLength+2 : OffsetExtensionLength+2+int(fp.ExtensionLength)]
				printFingerprint(fp)
				err := addFingerprint(db, filename, fp)
				if err != nil {
					fmt.Println(err)
				}
			default:
				//fmt.Println("=============")
				//fmt.Println("Other handshake type:")
				//fmt.Printf("%x\n", dtls[OffsetHandshakeType:])
			}

		}
	}
}

func analyze(db *sql.DB, field string) {
	var fields []string
	var identifiers []string

	rows, err := db.Query(fmt.Sprintf("SELECT %s FROM fingerprint group by %s", field, field))
	if err != nil {
		fmt.Printf("%s query failed: %v", field, err)
	}
	defer rows.Close()
	for rows.Next() {
		var fieldVal string
		if err := rows.Scan(&fieldVal); err != nil {
			fmt.Printf("Could not scan %s: %v", field, err)
			return
		}
		fields = append(fields, fieldVal)
	}

	for _, cl := range fields {
		var results []string
		rows, err := db.Query(fmt.Sprintf("SELECT type FROM fingerprint where %s = ? group by type", field), cl)
		if err != nil {
			fmt.Printf("type query failed: %v", err)
		}
		defer rows.Close()
		for rows.Next() {
			var res string
			if err := rows.Scan(&res); err != nil {
				fmt.Printf("Could not scan type for field %s: %v", field, err)
				return
			}
			results = append(results, res)
		}
		if len(results) == 1 && results[0] == "snowflake" {
			identifiers = append(identifiers, cl)
		}
	}
	if len(identifiers) > 0 {
		fmt.Printf("Identifiers for %s: %v\n", field, identifiers)
	} else {
		fmt.Printf("No identifiers were found for %s\n", field)
	}
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
		fmt.Println("Please provide action")
		os.Exit(1)
	}

	cmd := os.Args[1]

	if cmd == "analyze" {
		for _, field := range analyzeFields {
			analyze(db, field)
		}
		return
	} else if cmd != "fingerprint" {
		return
	}

	if len(os.Args) < 4 {
		fmt.Println("Please provide fingerprint type and a path to pcaps")
		os.Exit(1)
	}

	fingerprintType = os.Args[2]

	err = filepath.Walk(os.Args[3], func(path string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Println(err)
			return err
		}
		fmt.Printf("dir: %v: name: %s\n", info.IsDir(), info.Name())
		if !info.IsDir() && strings.Contains(info.Name(), ".pcap") {
			parsePcap(db, path, info.Name())
		}
		return nil
	})
	if err != nil {
		fmt.Println(err)
	}
}
