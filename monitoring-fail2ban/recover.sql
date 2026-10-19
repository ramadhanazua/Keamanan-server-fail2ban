PRAGMA foreign_keys=OFF;
BEGIN;
PRAGMA writable_schema = on;
CREATE TABLE IF NOT EXISTS  users (	id INTEGER NOT NULL, 	username VARCHAR(100) NOT NULL, 	password VARCHAR(255) NOT NULL, 	PRIMARY KEY (id), 	UNIQUE (username));
CREATE TABLE IF NOT EXISTS  security_event (
	id INTEGER NOT NULL, 
	tanggal DATETIME, 
	username VARCHAR(50), 
	ip VARCHAR(30), 
	file VARCHAR(100), 
	status VARCHAR(30), 
	action VARCHAR(100), 
	PRIMARY KEY (id)
);
INSERT INTO "users"("id", "username", "password") VALUES( 1, 'admin', 'scrypt:32768:8:1$FaGzxCdAT7YGgn9M$c613a023cf13abafec172933dcc03f4d9ebec81783888dd6e2bda80ddd9f591a7bf573e80f2371476e8deae2500458c707783968a8b57db7b88b1206d1870bad' );
PRAGMA writable_schema = off;
COMMIT;
