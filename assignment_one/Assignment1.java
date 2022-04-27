import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Random;
import java.io.UnsupportedEncodingException;
import java.io.File;
import java.io.BufferedWriter;
import java.io.FileWriter;

public class Assignment1 implements Assignment1Interface {

    // Convert publicModulus(n) hexadecimal string to BigInt.
    private static final BigInteger n = new BigInteger("c406136c12640a665900a9df4df63a84fc855927b729a3a106fb3f379e8e4190ebba442f67b93402e535b18a5777e6490e67dbee954bb02175e43b6481e7563d3f9ff338f07950d1553ee6c343d3f8148f71b4d2df8da7efb39f846ac07c865201fbb35ea4d71dc5f858d9d41aaa856d50dc2d2732582f80e7d38c32aba87ba9", 16);

    // Method generateKey returns the key as an array of bytes and is generated from the given password and salt.
    public byte[] generateKey(byte[] password, byte[] salt) {

        // Concatenate password and salt.
        byte[] key = new byte[password.length + salt.length];
        System.arraycopy(password, 0, key, 0, password.length);
        System.arraycopy(salt, 0, key, password.length, salt.length);

        // Hash key 200 times using SHA-256.
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            for (int i=0; i<200; i++) {

                key = digest.digest(key);

            }
        }

        catch (NoSuchAlgorithmException e) {
            System.err.println("I'm sorry, but SHA-256 is not a valid message digest algorithm");
        }

    return key;
    }

    // Convert password into corresponding bytes using UTF-8 encoding.
    private static byte[] convertPassword(String password) throws UnsupportedEncodingException {
        byte[] bytes = password.getBytes("UTF-8");
        return bytes;
    }

    // Generate salt using random 16 bytes.
    private static byte[] generateSalt() {
        Random r = new SecureRandom();
        byte[] bytes = new byte[16];
        r.nextBytes(bytes);
        return bytes;
    }

    // Generate IV using random 16 bytes.
    private static byte[] generateIV() {
        Random r = new SecureRandom();
        byte[] bytes = new byte[16];
        r.nextBytes(bytes);
        return bytes;
    }

    // Method encryptAES returns the AES encryption of the given plaintext as an array of bytes using the given iv and key.      
	public byte[] encryptAES(byte[] plaintext, byte[] iv, byte[] key) {
        
        try {
            SecretKeySpec AESKey = new SecretKeySpec(key, "AES");
            Cipher encryptor = Cipher.getInstance("AES/CBC/NoPadding");
            encryptor.init(Cipher.ENCRYPT_MODE, AESKey, new IvParameterSpec(iv));

            /* If the final part of the message is less than the block size,
            append a 1-bit and fill the rest of the block with 0-bits; if the final part of the message is equal to the block size,
            then create an extra block starting with a 1-bit and fill the rest of the block with 0-bits.
            */

            int paddingSize = 16 - (plaintext.length % 16);
            /*
            System.out.println(padding);
            */
            byte[] padded = new byte[plaintext.length + paddingSize];
            System.arraycopy(plaintext, 0, padded, 0, plaintext.length);
            padded[plaintext.length] = (byte) 128; // 1000 0000

            for (int j = (plaintext.length + 1); j < padded.length; j++) {
                
                padded[j] = (byte) 0; // 0
            }

            byte[] result = encryptor.doFinal(padded);
            return result;

        } 
        
        catch (Exception e) {

            e.printStackTrace();
            return plaintext;
        }
    }

    // Method decryptAES returns the AES decryption of the given ciphertext as an array of bytes using the given iv and key */  
    public byte[] decryptAES(byte[] ciphertext, byte[] iv, byte[] key) {

        try {
            SecretKeySpec AESKey = new SecretKeySpec(key, "AES");
            Cipher decryptor = Cipher.getInstance("AES/CBC/NoPadding");
            decryptor.init(Cipher.DECRYPT_MODE, AESKey, new IvParameterSpec(iv));

            byte[] result = decryptor.doFinal(ciphertext);
            return result;

        } catch (Exception e) {

            e.printStackTrace();
            return ciphertext;
        }

    }

    // Method encryptRSA returns the encryption of the given plaintext using the given encryption exponent and modulus.
    public byte[] encryptRSA(byte[] plaintext, BigInteger exponent, BigInteger modulus) {
        byte[] encryptedRSA = null;

        BigInteger b = new BigInteger(plaintext);
        BigInteger m = modExp(b, exponent, modulus);

        encryptedRSA = m.toByteArray();
        return encryptedRSA;
    }

    // Convert byte array to hexidecimal string.

    private static String convertByteToHex(byte[] bytes) {

        StringBuffer hex = new StringBuffer();
        for (byte b : bytes) {
            hex.append(String.format("%02X", b));
        }
        return hex.toString();
    }

    // Method modExp returns the result of raising the given base to the power of the given exponent using the given modulus.
    public BigInteger modExp(BigInteger base, BigInteger exponent, BigInteger modulus) {

        /* Calculating y=a^x (mod n) where the exponent x is k bits long:
        y = 1
        for i = 0 to k-1 do 
            if xi = 1 then y = (y*a) mod n end if
            a = (a*a) mod n
        end for */

        BigInteger y = new BigInteger("1");

        while (exponent.compareTo(BigInteger.ZERO) > 0) {

            if (exponent.testBit(0)) {
                y = (y.multiply(base).mod(modulus));
            }

            else {
                base = (base.multiply(base).mod(modulus));
            }
            exponent = exponent.shiftRight(1);
        }

        return y.mod(modulus);

    }
    
    public static void main(String[] args) throws UnsupportedEncodingException {

        Assignment1 cipher = new Assignment1();
        String password = "(c6q7Lv8xDNRP<Sc";
        byte[] convertedPassword = convertPassword(password);
        byte[] salt = generateSalt();
        
        
        // System.out.println("Password: " + password);
        // System.out.println("Converted password: " + convertedPassword);
        // System.out.println("Salt: " + salt);

        // Call generateKey() method.
        byte[] encryptionKey = cipher.generateKey(convertedPassword, salt);

        
        // System.out.println("Encryption key: " + encryptionKey);

        byte[] IV = generateIV();
        File file = new File(args[0]);
        BigInteger e = new BigInteger("65537");
        
        try {

            Path currentPath = Paths.get(System.getProperty("user.dir") + "/" + file);

            byte[] fileBytes = Files.readAllBytes(currentPath);

            byte[] encryptedText = cipher.encryptAES(fileBytes, IV, encryptionKey);
            // System.out.println(encryptedText);
            String encryptedHex = convertByteToHex(encryptedText);
            // System.out.println(encryptedHex);

            byte[] encryptedRSA = cipher.encryptRSA(convertedPassword, e, n);
            // System.out.println("Encrypted RSA: " + encryptedRSA);
            String hexRSA = convertByteToHex(encryptedRSA);
            // System.out.println("Hex RSA: " + hexRSA);


            // Writing 128-bit salt value (32 hex digits) to "Salt.txt".
            BufferedWriter saltFile = new BufferedWriter(new FileWriter("Salt.txt"));
            saltFile.write(convertByteToHex(salt));
            saltFile.close();

            // Writing 128-bit IV (32 hex digits) to "IV.txt".
            BufferedWriter ivFile = new BufferedWriter(new FileWriter("IV.txt"));
            ivFile.write(convertByteToHex(IV));
            ivFile.close();

            // Writing password encrypted using RSA in hexadecimal to "Password.txt".
            BufferedWriter passwordFile = new BufferedWriter(new FileWriter("Password.txt"));
            passwordFile.write(hexRSA);
            passwordFile.close();

            /* Testing decryptAES method.
            byte[] decryptedText = cipher.decryptAES(encryptedText, IV, encryptionKey);
            // System.out.println(decryptedText);
            String decryptedHex = convertByteToHex(decryptedText);
            // System.out.println(decryptedHex);

            // Testing - writing decrypted hex in "Test.txt".
            BufferedWriter testFile = new BufferedWriter(new FileWriter("Test.txt"));
            testFile.write(decryptedHex);
            testFile.close();
            */

            // System.out.println(encryptedHex);
            
            // Writing the AES encryption of the Assignment1.class file in hexadecimal to "Encryption.txt".
            BufferedWriter encryptionFile = new BufferedWriter(new FileWriter("Encryption.txt"));
            encryptionFile.write(encryptedHex);
            encryptionFile.close();

        }

        catch (Exception e1) {
        
            e1.printStackTrace();
        }
    }
}