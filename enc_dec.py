import os
import sys

from hashlib import sha1
from Crypto.Cipher import AES
from Crypto import Random


# parse the string key to oct key
#def toKey(stringKey):
#    key = []
#    for i in xrange(0, len(stringKey)):
#        key.append(ord(i))
#    return key

# Hash function of hmac_sha1
def hmac_sha1(key, msg):
    blocksize = sha1().block_size
    trans_5C = "".join(chr(x ^ 0x5c) for x in xrange(256))
    trans_36 = "".join(chr(x ^ 0x36) for x in xrange(256))
    
    if len(key) > blocksize:
        key = sha1(key).digest()
    key += chr(0) * (blocksize - len(key))
    o_key_pad = key.translate(trans_5C)
    i_key_pad = key.translate(trans_36)
    return sha1(o_key_pad + sha1(i_key_pad + msg).digest()).hexdigest()

# Initial xor for the vector and 1st block of msg
def xorString(iv, msg):
	xor = []
	for i in xrange(len(iv)):
		xor.append(chr(ord(msg[i]) ^ ord(iv[i])))
	return ''.join(xor)
    
# The AES encryption CBC mode using AES-ECB
def aes_cbc_enc(key, iv, msg):
	#print len(msg)
	cipher = ""
	for i in xrange(0, len(msg)/16):
		blockMsg = msg[i * 16: (i+1) * 16]
		print "Block " + str(i) + " is " + blockMsg
		blockMsg = xorString(iv, blockMsg)
		print "XORed block value is " + blockMsg
		aes = AES.new(key, AES.MODE_ECB)
		blockCipher = aes.encrypt(blockMsg)
		print "Encrypted block value is " + blockCipher
		iv = blockCipher
		print "New iv is " + iv + "\n"
		cipher += blockCipher
	print "\nThe final encrypted message is " + cipher
	return cipher
	
# The AES decryption CBC mode using AES-ECB
def aes_cbc_dec(key, iv, cipher):
	print len(cipher)
	newNewM = ""
	for i in xrange(0, len(cipher)/16):
		blockCipher = cipher[i * 16: (i+1) * 16]
		print "Block " + str(i) + " is " + blockCipher
		aes = AES.new(key, AES.MODE_ECB, iv)
		blockMsg = aes.decrypt(blockCipher)
		print "XORed block value is " + blockMsg
		blockMsg = xorString(iv, blockMsg)
		print "Decrypted block value is " + blockMsg
		iv = blockCipher
		print "New iv is " + iv + "\n"
		newNewM += blockMsg
	return newNewM

# Encryption function
def Enc():
	raw_input("Please \n1. store the 16-byte secret key Kenc in a file named 'kenc.txt'. \n2. the 16-byte secret key Kmac in a file named 'kmac.txt'. \n3. A file m.txt should contain variable-length octet string M. \nAll the files should within the same folder as this Python script \nPress ENTER when done...")
	# Check the file
	while 1:
		try:
			fknec = open("kenc.txt", "r") 
			fkmac = open("kmac.txt", "r") 
			fm = open("m.txt", "r")
			kenc = fknec.read(16)
			kmac = fkmac.read(16)
			m = fm.read().rstrip('\n')
			fknec.close()
			fkmac.close()
			fm.close()
			if (len(m) % 2) != 0:
				raw_input("\n\nInvalid plaintext!! Plaintext must be octet-string in bytes\nPlease check, press ENTER to close the program...")
				raise Exception()
			print "The Knec = " + kenc
			print "The Kmac = " + kmac
			print "The m = " + m
			
			#raw_input("haha");
		except IOError:
			raw_input("Files are invalid, please check, hit ENTER when done. Or hit Ctrl+C to quit the program")
		except BaseException, e:
			print e
			sys.exit()
		else:
			break
	
	# Start encryption
	macT = hmac_sha1(kmac, m)
	print "Calculating ... \nThe MAC tag T = " + macT
	newM = m + macT
	print "M' = " + newM
	n = (len(newM) / 2) % 16
	print "n = " + str(n)
	ps = ""
	if n != 0:
#		print hex((16 - n) ** 2)
		if (16 - n) < 10:
			tempValue = '0' + str(hex(16 - n))[2:]
		else:
			tempValue = str(hex(16 - n))[2:]
		for i in xrange(16 - n):
			ps += tempValue
#		print ps
	else:
		for i in xrange(16):
			ps += '10'
			
	print "PS = " + ps
	newNewM = newM + ps
	print "M'' = " + newNewM
	iv = Random.new().read(16)
	print "IV = " + iv
	c = aes_cbc_enc(kenc, iv, newNewM)
	output = iv + c
	f = open("c.txt", "w") # create a output file
	f.write(output)
	f.close()
	raw_input("\n\nSuccess! Encrypted message is outputed to the file [c.txt]... Press ENTER to close the program!")
	
	

# Decryption function
def Dec():
	raw_input("Please \n1. store the 16-byte secret key Kenc in a file named 'kenc.txt'. \n2. the 16-byte secret key Kmac in a file named 'kmac.txt'. \n3. A file c.txt should contain the encrypted message. \nAll the files should within the same folder as this Python script \nPress ENTER when done...")
	# Check the file
	while 1:
		try:
			fknec = open("kenc.txt", "r") 
			fkmac = open("kmac.txt", "r") 
			fc = open("c.txt", "r")
			kenc = fknec.read(16)
			kmac = fkmac.read(16)
			output = fc.read().rstrip('\n')
			fknec.close()
			fkmac.close()
			fc.close()
			print "The Knec = " + kenc
			print "The Kmac = " + kmac
			print "The IV||c = " + output
			
			#raw_input("haha");
		except IOError:
			raw_input("Files are invalid, please check, hit ENTER when done. Or hit Ctrl+C to quit the program")
		except BaseException, e:
			print e
		else:
			break
	# Start the decryption
	iv = output[:16]
	print "The IV = " + iv
	c = output[16:]
	print "The c = " + c
	newNewM = aes_cbc_dec(kenc, iv, c)
	print "M'' = " + newNewM
	n = newNewM[-2:]
	print "The pad byte is 0x" + n
	try:
		number = int(n, 16)
	except ValueError:
		raw_input("\n\nInvalid Ciphertext, don't try to screw this program xD\nPress ENTER to close the program")
		sys.exit()
	print "n = " + str(number)
	for i in xrange(number - 1):
		if newNewM[-2 * (i + 2): -2 * (i + 1)] != n:
			raw_input("\n\nInvalid Padding!! Are you sure the original plaintext is octet bytes? Don't use normal strings!'\nPlease check, click ENTER to close the program...")
			sys.exit()
	newM = newNewM[:len(newNewM) - number * 2]
	print "M' = " + newM
	macT = newM[-20 * 2:]
	print "MAC tag = " + macT
	m = newM[:-20 * 2]
	print "m = " + m
	newT = hmac_sha1(kmac, m)
	print "T' = " + newT
	if macT != newT:
		raw_input("\n\nInvalid MAC!!\nPlease check, click ENTER to close the program...")
		sys.exit()
	print "The decrypted message is: " + m
	f = open("decm.txt", "w") # create a output file
	f.write(m)
	f.close()
	raw_input("\n\nSuccess! Decrypted message is outputed to the file [decm.txt]... Press ENTER to close the program!")			


# main method
if __name__ == "__main__":
    # Choose menu
    while 1:
	    try:
		    option = int(raw_input("Please choose an option and press ENTER: \n1. Press 1 to encrypt. \n2. Press 2 to decrypt. \n"))
	    except BaseException, e:
		    print e
	    else:
		    break
	
	
    # Check the entered option value
    while option != 1 and option != 2:
	    try:
		    option = int(raw_input("Invalid option! Please re-enter: "))
	    except BaseException, e:
		    print e

    os.system('clear')

    # Call the choosed function
    if option == 1:
	    Enc()
    elif option == 2:
	    Dec()
    else:
	    raw_input("Unexpected error, will now exit... Press ENTER to close the program")



	

