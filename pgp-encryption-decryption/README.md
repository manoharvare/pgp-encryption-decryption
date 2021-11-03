# PGPEncryptDecryptFiles
### Spring Boot app which using Bouncy Castle library to encrypt and decrypt files.

Instructions to **generate public and secret key** to encrypt/decrypt files or messages:

- install "GnuPG (aka PGP/GPG)": 

		$ sudo apt-get install gnupg 
		$ sudo apt-get install rng-tools 
		$ sudo sed -i -e 's|#HRNGDEVICE=/dev/hwrng|HRNGDEVICE=/dev/urandom|' /etc/default/rng-tools 
		$ sudo service rng-tools start

- generate a key: 

		$ gpg --gen-key

- to view all keys: 
	
		$ gpg --list-keys

- export a public key: 

		$ gpg --export -a --output [path-to-public-key].asc [email-address]

- export a secret key: 

		$ gpg -a --export-secret-keys > [path-to-secret-key].asc


- Reference url for PGP implementation:
$ https://stackoverflow.com/questions/61826843/java-pgp-encryption-using-bouncy-castle
https://www.igolder.com/PGP/generate-key/

More informations @ [Installing and Using PGP](https://nsrc.org/workshops/2014/btnog/raw-attachment/wiki/Track3Agenda/2-1-1.pgp-lab.html)
