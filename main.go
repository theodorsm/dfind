package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/jackc/pgx/v5"
)

type Fingerprint struct {
	HandshakeType   uint
	Length          uint
	FragmentOffset  uint
	MajorVersion    byte
	MinorVersion    byte
	CookieLength    uint
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

var analyzeFields = []string{"length", "cookieLength", "cipherLength", "ciphers", "chosenCipher", "extensionLength", "extensions"}

func addFingerprint(db *pgx.Conn, filename string, fp Fingerprint) error {
	var result int
	err := db.QueryRow(context.Background(), "INSERT INTO fingerprint (type, filename, handshakeType, length, fragmentOffset, majorVersion, minorVersion, cookieLength, cipherLength, ciphers, chosenCipher, extensionLength, extensions) VALUES ($1, $2 , $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) RETURNING id", fingerprintType, filename, fp.HandshakeType, fp.Length, fp.FragmentOffset, int(fp.MajorVersion), int(fp.MinorVersion), fp.CookieLength, fp.CipherLength, hex.EncodeToString(fp.Ciphers), hex.EncodeToString(fp.ChosenCipher), fp.ExtensionLength, hex.EncodeToString(fp.Extensions)).Scan(&result)
	if err != nil {
		return fmt.Errorf("addFingerprint: %v\n", err)
	}
	fmt.Printf("Fingerprint ID: %d\n", result)
	return nil
}

func addFragment(db *pgx.Conn, filename string, fp Fingerprint, data []byte) error {
	var result int
	err := db.QueryRow(context.Background(), "INSERT INTO fragment (type, filename, handshakeType, fragmentOffset, data) VALUES ($1, $2 , $3, $4, $5) RETURNING id", fingerprintType, filename, fp.HandshakeType, fp.FragmentOffset, hex.EncodeToString(data)).Scan(&result)
	if err != nil {
		return fmt.Errorf("addFragment: %v\n", err)
	}
	fmt.Printf("Fragment ID: %d\n", result)
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
		fmt.Printf("Cookie length: %d\n", fp.CookieLength)
		fmt.Printf("Cipher suite length: %d\n", fp.CipherLength)
		fmt.Printf("Ciphers: %x\n", fp.Ciphers)
		fmt.Printf("Extension length: %d\n", fp.ExtensionLength)
		fmt.Printf("Extensions: %x\n", fp.Extensions)
	case ServerHelloType:
		fmt.Println("Server Hello:")
		fmt.Printf("Length: %d\n", fp.Length)
		fmt.Printf("Fragment Offset: %d\n", fp.FragmentOffset)
		fmt.Printf("DTLS v%d.%d\n", 0xff-fp.MajorVersion, 0xff-fp.MinorVersion)
		fmt.Printf("Cookie length: %d\n", fp.CookieLength)
		fmt.Printf("Chosen cipher suite: %x\n", fp.ChosenCipher)
		fmt.Printf("Extension length: %d\n", fp.ExtensionLength)
		fmt.Printf("Extensions: %x\n", fp.Extensions)
	default:
		return
	}
}

func parsePcap(db *pgx.Conn, path string, filename string) {
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
					addFragment(db, filename, fp, dtls[OffsetFragmentOffset+4:])
					return
				}
				fp.MajorVersion = dtls[OffsetMajorVersion]
				fp.MinorVersion = dtls[OffsetMinorVersion]
				OffsetCookieLength := OffsetSessionLength + int(dtls[OffsetSessionLength]) + 1
				fp.CookieLength = uint(dtls[OffsetCookieLength])
				OffsetCipherLength := OffsetCookieLength + int(fp.CookieLength) + 1
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
					addFragment(db, filename, fp, dtls[OffsetFragmentOffset+4:])
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

func analyze(db *pgx.Conn, field string) {
	var fields []string
	var identifiers []string

	rows, err := db.Query(context.Background(), fmt.Sprintf("SELECT %s FROM fingerprint group by %s", field, field))
	if err != nil {
		fmt.Printf("%s query failed: %v\n", field, err)
	}
	defer rows.Close()
	for rows.Next() {
		var fieldVal string
		if err := rows.Scan(&fieldVal); err != nil {
			fmt.Printf("Could not scan %s: %v\n", field, err)
			return
		}
		fields = append(fields, fieldVal)
	}

	for _, cl := range fields {
		var results []string
		rows, err := db.Query(context.Background(), fmt.Sprintf("SELECT type FROM fingerprint where %s = $1 group by type", field), cl)
		if err != nil {
			fmt.Printf("type query failed: %v\n", err)
		}
		defer rows.Close()
		for rows.Next() {
			var res string
			if err := rows.Scan(&res); err != nil {
				fmt.Printf("Could not scan type for field %s: %v\n", field, err)
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

func analyzeLev(db *pgx.Conn) {

	var extensionsArr []string
	var filenameArr []string
	rows, err := db.Query(context.Background(), fmt.Sprintf("SELECT extensions,filename FROM fingerprint WHERE type = 'snowflake'"))
	if err != nil {
		fmt.Printf("Snowflake extensions query failed: %v", err)
	}

	for rows.Next() {
		var extensions string
		var filename string
		if err := rows.Scan(&extensions, &filename); err != nil {
			fmt.Printf("Could not scan: %v\n", err)
			return
		}
		extensionsArr = append(extensionsArr, extensions)
		filenameArr = append(filenameArr, filename)
	}
	rows.Close()

	for i, extension := range extensionsArr {
		innerRows, err := db.Query(context.Background(), fmt.Sprintf("select type, extensions, filename, levenshtein(extensions, $1) from fingerprint where type != 'snowflake' and levenshtein(extensions, $2) BETWEEN 1 AND 20"), extension, extension)
		if err != nil {
			fmt.Printf("Levenshtein query failed: %v\n", err)
		}
		for innerRows.Next() {
			var innerExtensions string
			var filename string
			var fingerprintType string
			var distance int
			if err := innerRows.Scan(&fingerprintType, &innerExtensions, &filename, &distance); err != nil {
				fmt.Printf("Could not scan extensions: %v\n", err)
				return
			}
			fmt.Printf("Levenshtein distance: %d\n", distance)
			fmt.Println(filenameArr[i])
			fmt.Println(extension)
			fmt.Println(filename)
			fmt.Println(innerExtensions)
		}
		innerRows.Close()
	}
}

func main() {

	url := "postgres://postgres:@localhost:5432/dtls_fingerprinting"
	//db, err := pgx.Connect(context.Background(), os.Getenv("DATABASE_URL"))
	db, err := pgx.Connect(context.Background(), url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close(context.Background())

	pingErr := db.Ping(context.Background())
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
	} else if cmd == "extensions" {
		analyzeLev(db)
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
