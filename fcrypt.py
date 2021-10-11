import sys
import base64
from optparse import OptionParser
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from os import urandom

def encrypt(key, source, dest):
#	print("Attempting to Encrypt!")

	# This generates a random AES key	
	aesKey = urandom(16)
	
	# This block of code encrypts the file with AES, then encodes it to base64 and decodes it for storage
	aes_enc_obj = AES.new(aesKey, AES.MODE_GCM)
	ciphertext, tag = aes_enc_obj.encrypt_and_digest(source)
	encdNonce = (base64.b64encode(aes_enc_obj.nonce)).decode("utf-8")
	encdCipher = (base64.b64encode(ciphertext)).decode("utf-8")
	encdTag = (base64.b64encode(tag)).decode("utf-8")
	
	# This prints the encrypted data to the destination file
	with open(dest, 'w') as f:
		print(f"{encdCipher}\n{encdTag}\n{encdNonce}", file=f)
		f.close()
		
	# This imports the private RSA key for encrypting the AES key
	with open(key, 'rb') as rFile:
		rsaKey = RSA.importKey(rFile.read())
		rFile.close()
	
	# This code uses the RSA key to encrypt the AES key, then it is encoded in base64
	# and decoded for storage
	rsa_enc_obj = PKCS1_OAEP.new(rsaKey)
	encdKey = base64.b64encode(rsa_enc_obj.encrypt(aesKey)).decode("utf-8")
	
	# This writes the encrypted AES key to aes.txt
	with open("aes.txt", 'w') as a:
		print(f"{encdKey}", file=a)
		a.close()
		
	# This lets the user know that the operation was a success
	print("Successfully encrypted!")
		
def decrypt(key, sourceList, dest):
#	print("Attempting to Decrypt!")
	
	# This imports the public RSA key
	with open(key, 'rb') as r:
		rsapKey = RSA.importKey(r.read())
		r.close()	
		
	# This imports the encrypted AES key	
	with open("aes.txt", 'r') as aFile:
		encdKey = aFile.read()
		aFile.close()
	
	# This block of code decyptes the AES key for the file receiver
	rsa_dec_obj = PKCS1_OAEP.new(rsapKey)
	rsaKey = base64.b64decode(encdKey)
	aesKey = rsa_dec_obj.decrypt(rsaKey)	
	
	# This pulls the encrypted cipher, tag, and nonce from the list and decodes it from base64
	eCipher = base64.b64decode(sourceList[0].strip())
	eTag    = base64.b64decode(sourceList[1].strip())
	eNonce  = base64.b64decode(sourceList[2].strip())
	
	# This line of code decrypts the AES ciphertext
	aes_dec_obj = AES.new(aesKey, AES.MODE_GCM, nonce=eNonce)
	decrypted = (aes_dec_obj.decrypt_and_verify(eCipher, eTag)).decode("utf-8").strip()
		 
	# This saves the decrypted test to the destination file
	with open(dest, 'w') as d:	 
		print(f"{decrypted}", file=d)
		d.close()
		
	# This lets the user know that the operation was a success
	print("Successfully decrypted!")

def Main():

	# This parses the options to find out which process the user wishes to run
	parser = OptionParser()

	parser.add_option('--encrypt',
						dest = 'encrypt',
						help = 'file to encrypt',
						metavar = 'FILE')
	parser.add_option('--decrypt',
						dest = 'decrypt',
						help = 'file to decrypt',
						metavar = 'FILE')

	(options,args) = parser.parse_args()
	
	# This stores the name of the provided keyfile
	key = sys.argv[2]
	
	# This reads the provided sourcefile, and reads it according to the option selected
	sFile = sys.argv[3]
	with open(sFile, 'r') as s:
		if (options.encrypt != None):
			source = s.read().encode("utf-8")
		if (options.decrypt != None):
			s.seek(0)
			sourceList = s.readlines()
		s.close()
	
	# This stores the name of the destination file
	dest = sys.argv[4]

	# This calls the requested operation
	if (options.encrypt != None):
		encrypt(key, source, dest)

	if (options.decrypt != None):
		decrypt(key, sourceList, dest)

# Driver code for main function

if __name__ == '__main__':
	Main()

