import java.math.BigInteger;

	interface Assignment1Interface {
	 
        /* Method generateKey returns the key as an array of bytes and is generated from the given password and salt. */
        
		byte[] generateKey(byte[] password, byte[] salt);
		
        /* Method encryptAES returns the AES encryption of the given plaintext as an array of bytes using the given iv and key */
           
		byte[] encryptAES(byte[] plaintext, byte[] iv, byte[] key);
		
        /* Method decryptAES returns the AES decryption of the given ciphertext as an array of bytes using the given iv and key */
        
        byte[] decryptAES(byte[] ciphertext, byte[] iv, byte[] key);
				
        /* Method encryptRSA returns the encryption of the given plaintext using the given encryption exponent and modulus */
        
        byte[] encryptRSA(byte[] plaintext, BigInteger exponent, BigInteger modulus);
	 
        /* Method modExp returns the result of raising the given base to the power of the given exponent using the given modulus */
        
        BigInteger modExp(BigInteger base, BigInteger exponent, BigInteger modulus);
        
	}

