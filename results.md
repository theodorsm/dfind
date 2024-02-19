
## Fingerprint 1

- windows_firefox_snowflake_472.pcap
- Fuzzy:     00170000ff01000100000a00080006001d00170018000b0002010000230000000d00140012040308040401050308050501080606010201000e00050002000100
- Snowflake: 00170000ff01000100000a00080006001d00170018000b0002010000230000000d00140012040308040401050308050501080606010201000e0009000600010008000700
- Match filename: ubuntu_chrome_discord_1008.pcap
- Handshake: client hello
- Extension: use_srtp. 
  - Fields: len=9, SRTP protection profiles length: 6
  - Unique fields: SRTP_AEAD_AES_256_GCM (0x0008), SRTP_AEAD_AES_128_GCM (0x0007)
- Fingerprint: 0e0009000600010008000700

## Fingerprint 2

- windows_firefox_snowflake_488.pcap
- Fuzzy:     00170000000e00050002000100000a00080006001d00170018000b00020100
- Snowflake: 000e00050002000100000a00080006001d00170018000b00020100
- Match filename: ubuntu_firefox_facebook_1149.pcap
- Handshake: server hello
- Fingerprint: snowflake missing the extended_master_secret (len=0) as the first extension.
- Note: other snowflake handshakes had the exact extensions as the fuzzy match.

## Fingerprint 3

- windows_firefox_snowflake_488.pcap
- Fuzzy:     00170000ff01000100000b00020100000e00050002000100
- Snowflake: 000e00050002000100000a00080006001d00170018000b00020100
- Match filename: ubuntu_firefox_facebook_108.pcap
- Handshake: server hello
- Fingerprint: snowflake missing the extended_master_secret (len=0) as the first extension and different order of extensions.


## Fingerprint 4

- windows_firefox_snowflake_488.pcap
- Fuzzy:     00170000ff01000100000b0002010000230000000e00050002000100
- Snowflake: 000e00050002000100000a00080006001d00170018000b00020100
- Match filename: ubuntu_chrome_google_166.pcap
- Handshake: server hello Fingerprint: snowflake missing the session_ticket (len=0) extension
- Note: snowflake uses this exact extension also

## Fingerprint 5

- windows_firefox_snowflake_488.pcap
- Fuzzy:     00170000ff01000100000a00080006001d00170018000b000201000010001200100677656272746308632d776562727463000d0020001e040305030603020308040805080604010501060102010402050206020202001c00024000000e000b0008000700080001000200
- Snowflake: ff01000100000a00080006001d00170018000b000201000010001200100677656272746308632d776562727463000d0020001e040305030603020308040805080604010501060102010402050206020202001c00024000000e000b0008000700080001000200
- Match filename: ubuntu_firefox_discord_100.pcap
- Handshake: client hello
- Fingerprint: snowflake missing the extended_master_secret (len=0) as the first extension.
- Note: other snowflake handshakes had the exact extensions as the fuzzy match.

## Fingerprint 6

- windows_firefox_snowflake_414.pcap
- Fuzzy:     00170000ff01000100000a00080006001d00170018000b000201000010001200100677656272746308632d776562727463000d0020001e040305030603020308040805080604010501060102010402050206020202001c00024000000e000b0008000700080001000200 
- Snowflake: 00170000ff01000100000a00080006001d00170018000b000201000010001200100677656272746308632d776562727463000d0018001604030503060302030804080508060401050106010201001c00024000000e000b0008000700080001000200 
- Match filename: ubuntu_firefox_discord_100.pcap
- Handshake: client hello
- Fingerprint: snowflake missing the signature algorithms: SHA256 DSA (0x0402), SHA384 DSA (0x0502), SHA512 DSA (0x0602), SHA1 DSA (0x0202)
- Note: other snowflake handshakes had the exact extensions as the fuzzy match.

## Fingerprint 7

- ubuntu_firefox_snowflake_425.pcap
- Fuzzy:     00170000ff01000100000a00080006001d00170018000b0002010000230000000d00140012040308040401050308050501080606010201000e00050002000100
- Snowflake: 00170000ff01000100000a00080006001d00170018000b0002010000230000000d00140012040308040401050308050501080606010201000e0009000600080007000100
- Match filename: ubuntu_chrome_discord_1008.pcap
- Handshake: client hello
- Extension: use_srtp. 
  - Fields: len=9, SRTP protection profiles length: 6
  - Unique fields: SRTP_AEAD_AES_256_GCM (0x0008), SRTP_AEAD_AES_128_GCM (0x0007)
- Fingerprint: 0e0009000600010008000700
- Note: other snowflake handshakes had the exact extensions as the fuzzy match.








