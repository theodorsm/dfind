package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcap"
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

type Extension struct {
	Type   uint
	Length uint
	Value  []byte
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
const HelloVerifyRequest = 0x3

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

func addHelloVerify(db *pgx.Conn, filename string, data []byte) error {
	var result int
	err := db.QueryRow(context.Background(), "INSERT INTO hello_verify (type, filename, data) VALUES ($1, $2 , $3) RETURNING id", fingerprintType, filename, hex.EncodeToString(data)).Scan(&result)
	if err != nil {
		return fmt.Errorf("addHelloVerify: %v\n", err)
	}
	fmt.Printf("Hello verify ID: %d\n", result)
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

func doubleByteLength(buf []byte, offset int) uint {
	return uint(buf[offset+1]) | uint(buf[offset])<<8
}

func tripleByteLength(buf []byte, offset int) uint {
	return uint(buf[offset+2]) | uint(buf[offset+1])<<8 | uint(buf[offset])<<16
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
				fp.Length = tripleByteLength(dtls, OffsetLength)
				fp.FragmentOffset = tripleByteLength(dtls, OffsetFragmentOffset)
				fragmentLength := tripleByteLength(dtls, OffsetFragmentOffset+3)
				if fragmentLength != fp.Length {
					// TODO: parse fragemented records
					err := addFragment(db, filename, fp, dtls[OffsetFragmentOffset+4:])
					if err != nil {
						fmt.Println(err)
					}
					return
				}
				fp.MajorVersion = dtls[OffsetMajorVersion]
				fp.MinorVersion = dtls[OffsetMinorVersion]
				OffsetCookieLength := OffsetSessionLength + int(dtls[OffsetSessionLength]) + 1
				fp.CookieLength = uint(dtls[OffsetCookieLength])
				OffsetCipherLength := OffsetCookieLength + int(fp.CookieLength) + 1
				fp.CipherLength = doubleByteLength(dtls, OffsetCipherLength)
				fp.Ciphers = dtls[OffsetCipherLength+2 : OffsetCipherLength+2+int(fp.CipherLength)]
				OffsetCompressionLength := OffsetCipherLength + 2 + int(fp.CipherLength) + 1
				OffsetExtensionLength := OffsetCompressionLength + int(dtls[OffsetCompressionLength]) + 1
				fp.ExtensionLength = doubleByteLength(dtls, OffsetExtensionLength)

				extensionBytes := dtls[OffsetExtensionLength+2 : OffsetExtensionLength+2+int(fp.ExtensionLength)]

				fp.Extensions = extensionBytes

				for len(extensionBytes) != 0 {
					extType := doubleByteLength(extensionBytes, 0)
					extLen := doubleByteLength(extensionBytes, 2)
					extValue := extensionBytes[4 : 4+extLen]
					ext := Extension{extType, extLen, extValue}
					extensionBytes = extensionBytes[4+extLen:]
					fmt.Println("PARSED EXTENSION: ")
					fmt.Println(ext)
				}

				printFingerprint(fp)
				err := addFingerprint(db, filename, fp)
				if err != nil {
					fmt.Println(err)
				}
			case ServerHelloType:
				fp.Length = tripleByteLength(dtls, OffsetLength)
				fp.FragmentOffset = tripleByteLength(dtls, OffsetFragmentOffset)
				fragmentLength := tripleByteLength(dtls, OffsetFragmentOffset+3)
				if fragmentLength != fp.Length {
					err := addFragment(db, filename, fp, dtls[OffsetFragmentOffset+4:])
					if err != nil {
						fmt.Println(err)
					}
					return
				}
				fp.MajorVersion = dtls[OffsetMajorVersion]
				fp.MinorVersion = dtls[OffsetMinorVersion]
				OffsetChosenCipher := OffsetSessionLength + int(dtls[OffsetSessionLength]) + 1
				fp.ChosenCipher = dtls[OffsetChosenCipher : OffsetChosenCipher+2]
				OffsetExtensionLength := OffsetChosenCipher + 3
				fp.ExtensionLength = doubleByteLength(dtls, OffsetExtensionLength)
				fp.Extensions = dtls[OffsetExtensionLength+2 : OffsetExtensionLength+2+int(fp.ExtensionLength)]
				printFingerprint(fp)
				err := addFingerprint(db, filename, fp)
				if err != nil {
					fmt.Println(err)
				}
			case HelloVerifyRequest:
				err := addHelloVerify(db, filename, dtls[OffsetHandshakeType+1:])
				if err != nil {
					fmt.Println(err)
					return
				}
			default:
				/*
					fmt.Println("=============")
					fmt.Println("Other handshake type:")
					fmt.Printf("%x\n", dtls[OffsetHandshakeType:])
				*/
			}

		}
	}
}

func analyze(db *pgx.Conn, field string, fpType string) {
	var fields []string
	var identifiers []string

	// UNSAFE SQL
	rows, err := db.Query(context.Background(), fmt.Sprintf("SELECT %s FROM fingerprint where type = $1 group by %s", field, field), fpType)
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

	numExt := 0

	for _, cl := range fields {
		var results []string
		// UNSAFE SQL
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
		if len(results) == 1 && results[0] == fpType {
			identifiers = append(identifiers, cl)
			if field == "extensions" {
				rows, err = db.Query(context.Background(), "SELECT count(id) FROM fingerprint where extensions = $1", cl)
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
					tmp, _ := strconv.Atoi(res)
					numExt += tmp
				}
			}
		}
	}
	if len(identifiers) > 0 {
		fmt.Printf("Identifiers for %s (#%d): %v\n", field, len(identifiers), identifiers)
		if field == "extensions" {
			fmt.Printf("Total numer of messages with unique extensions %d\n", numExt)
		}
	} else {
		fmt.Printf("No identifiers were found for %s\n", field)
	}

}

func analyzeLev(db *pgx.Conn, fpType string) {

	type ext struct {
		Extensions string
		Id         int
	}

	var extArr []ext

	rows, err := db.Query(context.Background(), fmt.Sprintf("SELECT max(id), extensions FROM fingerprint WHERE type = $1 group by extensions"), fpType)
	if err != nil {
		fmt.Printf("Extensions query failed: %v", err)
	}

	for rows.Next() {
		se := ext{}
		if err := rows.Scan(&se.Id, &se.Extensions); err != nil {
			fmt.Printf("Could not scan: %v\n", err)
			return
		}
		extArr = append(extArr, se)
	}
	rows.Close()

	for _, se := range extArr {
		cmpRows, err := db.Query(context.Background(), fmt.Sprintf("SELECT count(id), extensions, levenshtein(extensions, $1) FROM fingerprint WHERE type != $2 AND levenshtein(extensions, $3) BETWEEN 1 AND 32 GROUP BY extensions"), se.Extensions, fpType, se.Extensions)
		if err != nil {
			fmt.Printf("Levenshtein query failed: %v\n", err)
		}
		type fuzzyCmp struct {
			CmpExtensions string
			Distance      int
			Count         int
		}

		var fuzzyCmpArr []fuzzyCmp

		for cmpRows.Next() {
			fc := fuzzyCmp{}
			if err := cmpRows.Scan(&fc.Count, &fc.CmpExtensions, &fc.Distance); err != nil {
				fmt.Printf("Could not scan extensions: %v\n", err)
				return
			}
			fuzzyCmpArr = append(fuzzyCmpArr, fc)
		}
		cmpRows.Close()

		for _, fc := range fuzzyCmpArr {
			fmt.Printf("Levenshtein distance: %d\n", fc.Distance)
			fmt.Println(se.Extensions)
			fmt.Println(fc.Count)
			fmt.Println(fc.CmpExtensions)

			var result int
			err := db.QueryRow(context.Background(), "INSERT INTO fuzzy_extensions (type_id, levenshtein, extensions) VALUES ($1, $2 , $3) RETURNING id", se.Id, fc.Distance, fc.CmpExtensions).Scan(&result)
			if err != nil {
				fmt.Printf("Error on insert fuzzy_extensions: %v\n", err)
			}
			fmt.Printf("fuzzy_extensions ID: %d\n", result)
		}
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

	if len(os.Args) < 3 {
		fmt.Println("Please provide action and fingerprint type")
		os.Exit(1)
	}

	fingerprintType = os.Args[2]

	if cmd == "analyze" {
		for _, field := range analyzeFields {
			analyze(db, field, fingerprintType)
		}
		return
	} else if cmd == "extensions" {
		analyzeLev(db, fingerprintType)
		return
	} else if cmd != "fingerprint" {
		return
	}

	if len(os.Args) < 4 {
		fmt.Println("Please provide action, fingerprint type and a path to pcaps")
		os.Exit(1)
	}

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
