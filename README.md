# dfind

*dfind* is a tool for discovering passive fingerprints by finding identifying fields specific to different DTLS implementations.

## Requirements

- Postgres
- Go

## Usage

`<TAG>`: a string (no spaces) for tagging traffic. Examples: snowflake, chrome, firefox.
```bash
# Create tables in database
psql -h localhost -d dtls_fingerprinting -U postgres -f ./create-tables.sql
# Parse pcaps and insert into database
go run main.go fingerprint <TAG> <PATH-TO-PCAPS-FOLDER>
go run main.go fingerprint <ANOTHER-TAG> <PATH-TO-PCAPS-FOLDER>
go run main.go fingerprint <YET-ANOTHER-TAG> <PATH-TO-PCAPS-FOLDER>
# Automatic analysis of fingerprints
go run main.go analyze <TAG>
# Fuzzy matching of extensions, to be further analyzed further manually
go run main.go extensions <TAG>
```

## Disclaimer

This code-base contains unsafe and unsanitized SQL-queries, do not expose service to untrusted users. Only use locally for research purposes.
