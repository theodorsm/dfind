DROP TABLE IF EXISTS fingerprint;
CREATE TABLE fingerprint(
  id              SERIAL PRIMARY KEY,
  type            VARCHAR(255) NOT NULL,
  filename        VARCHAR(255) NOT NULL,
	handshakeType   INT NOT NULL, 
	length          INT NOT NULL,
	fragmentOffset  INT NOT NULL,
	majorVersion    INT NOT NULL, 
	minorVersion    INT NOT NULL,
  cookieLength    INT, 
	cipherLength    INT,
	ciphers         VARCHAR(255),
	chosenCipher    VARCHAR(4), 
	extensionLength INT NOT NULL,
	extensions      VARCHAR(500) NOT NULL
);

DROP TABLE IF EXISTS fragment;
CREATE TABLE fragment(
  id              SERIAL PRIMARY KEY,
  type            VARCHAR(255) NOT NULL,
  filename        VARCHAR(255) NOT NULL,
	handshakeType   INT NOT NULL, 
	fragmentOffset  INT NOT NULL,
	data            VARCHAR(1500) NOT NULL
);

DROP TABLE IF EXISTS fuzzy_extensions;
CREATE TABLE fuzzy_extensions(
  id              SERIAL PRIMARY KEY,
  type_id    INT NOT NULL,
	levenshtein   INT NOT NULL, 
	extensions      VARCHAR(500) NOT NULL
);

DROP TABLE IF EXISTS hello_verify;
CREATE TABLE hello_verify(
  id              SERIAL PRIMARY KEY,
  type            VARCHAR(255) NOT NULL,
  filename        VARCHAR(255) NOT NULL,
	data            VARCHAR(1500) NOT NULL
);
