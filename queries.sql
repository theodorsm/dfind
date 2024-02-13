select COUNT(id), extensions from fingerprint group by extensions;
-- 44 rows, snowflake

select COUNT(id), ciphers from fingerprint group by ciphers;
-- 8 rows, snowflake
-- +-----------+--------------------------------------------------+
-- | COUNT(id) | ciphers                                          |
-- +-----------+--------------------------------------------------+
-- |       990 |                                                  |
-- |        93 | 13011303c02bc02fcca9cca8c00ac009c013c014         |
-- |       143 | c02bc02fc00ac014                                 |
-- |       132 | c02bc02fc00ac014c0acc0ae                         |
-- |      1007 | c02bc02fcca9cca8c009c013c00ac014009c002f0035000a |
-- |      2856 | c02bc02fcca9cca8c00ac009c013c014                 |
-- |        11 | c02bc02fcca9cca8c00ac009c014                     |
-- |       124 | cca9cca8c02bc02fc009c013c00ac014009c002f0035000a |
-- +-----------+--------------------------------------------------+

select COUNT(id), extensionLength from fingerprint group by extensionLength;
-- 10 rows, snowflake
-- +-----------+-----------------+
-- | COUNT(id) | extensionLength |
-- +-----------+-----------------+
-- |        20 |              27 |
-- |       970 |              31 |
-- |       275 |              49 |
-- |      1059 |              64 |
-- |        72 |              68 |
-- |        63 |              98 |
-- |        94 |             102 |
-- |      2710 |             106 |
-- |        46 |             161 |
-- |        47 |             187 |
-- +-----------+-----------------+
--
select COUNT(id), type, extensionLength from fingerprint where type = 'snowflake' group by extensionLength;
-- +-----------+-----------+-----------------+
-- | COUNT(id) | type      | extensionLength |
-- +-----------+-----------+-----------------+
-- |        20 | snowflake |              27 |
-- |       970 | snowflake |              31 |
-- |       275 | snowflake |              49 |
-- |      1059 | snowflake |              64 |
-- |        72 | snowflake |              68 |
-- |        63 | snowflake |              98 |
-- |        94 | snowflake |             102 |
-- |      2710 | snowflake |             106 |
-- |        46 | snowflake |             161 |
-- |        47 | snowflake |             187 |
-- +-----------+-----------+-----------------+
select COUNT(id), type, extensionLength from fingerprint where type = 'discord' group by extensionLength;
-- +-----------+---------+-----------------+
-- | COUNT(id) | type    | extensionLength |
-- +-----------+---------+-----------------+
-- |       990 | discord |              22 |
-- |       997 | discord |              26 |
-- |      2009 | discord |              64 |
-- |      1110 | discord |             106 |
-- +-----------+---------+-----------------+
--
select COUNT(id), type, extensions from fingerprint where extensionLength = 64 group by extensions;
-- Note that first extension contain fingerprints from discord also. The second extension starts with "renegotiation_info" and is only for snowflake.
-- +-----------+-----------+----------------------------------------------------------------------------------------------------------------------------------+
-- | COUNT(id) | type      | extensions                                                                                                                       |
-- +-----------+-----------+----------------------------------------------------------------------------------------------------------------------------------+
-- |      3064 | snowflake | 00170000ff01000100000a00080006001d00170018000b0002010000230000000d00140012040308040401050308050501080606010201000e00050002000100 |
-- |         4 | snowflake | ff010001000017000000230000000d00140012040308040401050308050501080606010201000e00050002000100000b00020100000a00080006001d00170018 |
-- +-----------+-----------+----------------------------------------------------------------------------------------------------------------------------------+
--
select COUNT(id), type, extensionLength from fingerprint where type = 'google' group by extensionLength;
-- +-----------+--------+-----------------+
-- | COUNT(id) | type   | extensionLength |
-- +-----------+--------+-----------------+
-- |       772 | google |              24 |
-- |       474 | google |              28 |
-- |      1657 | google |              64 |
-- +-----------+--------+-----------------+
--



-- +-----------+-----------+--------------+
-- | COUNT(id) | type      | cipherLength |
-- +-----------+-----------+--------------+
-- |       990 | snowflake |            0 |
-- |       143 | snowflake |            8 |
-- |       132 | snowflake |           12 |
-- |        11 | snowflake |           14 |
-- |      2856 | snowflake |           16 |
-- |        93 | snowflake |           20 |
-- |      1131 | snowflake |           24 |
-- +-----------+-----------+--------------+
-- +-----------+---------+--------------+
-- | COUNT(id) | type    | cipherLength |
-- +-----------+---------+--------------+
-- |      1987 | discord |            0 |
-- |      1110 | discord |           16 |
-- |      2009 | discord |           24 |
-- +-----------+---------+--------------+
-- +-----------+--------+--------------+
-- | COUNT(id) | type   | cipherLength |
-- +-----------+--------+--------------+
-- |      1246 | google |            0 |
-- |      1657 | google |           30 |
-- +-----------+--------+--------------+
-- +-----------+----------+--------------+
-- | COUNT(id) | type     | cipherLength |
-- +-----------+----------+--------------+
-- |      1866 | facebook |            0 |
-- |      1493 | facebook |           16 |
-- |       181 | facebook |           24 |
-- +-----------+----------+--------------+
