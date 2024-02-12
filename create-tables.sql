DROP TABLE IF EXISTS fingerprint;
CREATE TABLE fingerprint(
  id              INT AUTO_INCREMENT NULL,
  type            VARCHAR(255) NOT NULL,
	handshakeType   INT NOT NULL, 
	length          INT NOT NULL,
	fragmentOffset  INT NOT NULL,
	majorVersion    INT NOT NULL, 
	minorVersion    INT NOT NULL,
	cipherLength    INT,
	ciphers         VARCHAR(255),
	chosenCipher    VARCHAR(4), 
	extensionLength INT NOT NULL,
	extensions      VARCHAR(255) NOT NULL,
  PRIMARY KEY(`id`)
);
