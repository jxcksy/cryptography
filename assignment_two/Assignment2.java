import java.math.BigInteger;
import java.security.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.io.File;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;

public class Assignment2 implements Assignment2Interface {

    public static void main(String[] args) throws IOException {

        // Convert prime modulus (p) hexadecimal string to BigInt
        final BigInteger p = new BigInteger("b59dd79568817b4b9f6789822d22594f376e6a9abc0241846de426e5dd8f6eddef00b465f38f509b2b18351064704fe75f012fa346c5e2c442d7c99eac79b2bc8a202c98327b96816cb8042698ed3734643c4c05164e739cb72fba24f6156b6f47a7300ef778c378ea301e1141a6b25d48f1924268c62ee8dd3134745cdf7323", 16);

        // Convert generator (g) hexadecimal string to BigInt
        final BigInteger g = new BigInteger("44ec9d52c8f9189e49cd7c70253c2eb3154dd4f08467a64a0267c9defe4119f2e373388cfa350a4e66e432d638ccdc58eb703e31d4c84e50398f9f91677e88641a2d2f6157e2f4ec538088dcf5940b053c622e53bab0b4e84b1465f5738f549664bd7430961d3e5a2e7bceb62418db747386a58ff267a9939833beefb7a6fd68", 16);

        // Generate random secret key x with 0 < x < p-1
        int keyLength = p.bitLength() - 1; // ensure length of key is less than p
        SecureRandom firstRandom = new SecureRandom();
        BigInteger x = new BigInteger(keyLength, firstRandom);

        Assignment2 a = new Assignment2();
        BigInteger y = a.generateY(g, x, p);
        File file = new File(args[0]);
        
        try {

            Path currentPath = Paths.get(System.getProperty("user.dir") + "/" + file);

            byte[] fileBytes = Files.readAllBytes(currentPath);
            BigInteger s = a.generateS(fileBytes, x, p);

            // Writing digital signature s in hexadecimal to "s.txt".
            BufferedWriter sFile = new BufferedWriter(new FileWriter("s.txt"));
            sFile.write(s.toString(16));
            sFile.close();

        }

        catch (Exception e) {

            e.printStackTrace();
        }


    }


    // Method used to generate random value k with 1 < k < p-1 and gcd(k, p-1) = 1
    public BigInteger generateK(BigInteger k, BigInteger tmp, BigInteger pminus1, int keyLength) {

        while(!tmp.equals(BigInteger.ONE)){

            SecureRandom thirdRandom = new SecureRandom();
            k = new BigInteger(keyLength, thirdRandom);
            // System.out.println("Calculating GCD for generateK()");
            tmp = calculateGCD(k, pminus1);

        }

        return k;
    }

    // Method generateS generates the second part of the ElGamal signature from the given plaintext, secretKey, first signature part r, random value k and modulus
    public BigInteger generateS(byte[] plaintext, BigInteger secretKey, BigInteger modulus) throws IOException {

        BigInteger s = BigInteger.ZERO;

        while (s.equals(BigInteger.ZERO)) {

            Assignment2 ass = new Assignment2();

            // Convert generator (g) hexadecimal string to BigInt
            final BigInteger g = new BigInteger("44ec9d52c8f9189e49cd7c70253c2eb3154dd4f08467a64a0267c9defe4119f2e373388cfa350a4e66e432d638ccdc58eb703e31d4c84e50398f9f91677e88641a2d2f6157e2f4ec538088dcf5940b053c622e53bab0b4e84b1465f5738f549664bd7430961d3e5a2e7bceb62418db747386a58ff267a9939833beefb7a6fd68", 16);

            // Generate random value k with 1 < k < p-1 and gcd(k, p-1) = 1
            int keyLength = modulus.bitLength() - 1; // ensure length of key is less than p
            BigInteger pminus1 = modulus.subtract(BigInteger.ONE);
            BigInteger tmp = BigInteger.ZERO;
            SecureRandom secondRandom = new SecureRandom();
            BigInteger pre = new BigInteger(keyLength, secondRandom);
            BigInteger k = ass.generateK(pre, tmp, pminus1, keyLength);

            // Compute r as r = g^k (mod p)
            BigInteger r = ass.generateR(g, k, modulus);

            // Writing digital signature r in hexadecimal to "r.txt".
            BufferedWriter rFile = new BufferedWriter(new FileWriter("r.txt"));
            rFile.write(r.toString(16));
            rFile.close();

            // Hash message (m)
            byte[] hashedFile = generateSHA256(plaintext);

            // Compute H(m)
            BigInteger hashedMessage = new BigInteger(hashedFile);

            // Compute xr
            BigInteger xr = secretKey.multiply(r);

            // Compute H(m) - xr
            s = hashedMessage.subtract(xr);
            
            try {
                s = s.multiply(calculateInverse(k, pminus1));
                s = s.mod(pminus1);
            }

            catch(ArithmeticException e){
                s = BigInteger.ZERO;
            }




    }

    return s;
    }

    // Method generateY returns the public key y and is generated from the given generator, secretKey and modulus
    public BigInteger generateY(BigInteger generator, BigInteger secretKey, BigInteger modulus) throws IOException {

        BigInteger y = generator.modPow(secretKey, modulus);

        // Writing public key y in hexadecimal to "y.txt".
        BufferedWriter yFile = new BufferedWriter(new FileWriter("y.txt"));
        yFile.write(y.toString(16));
        yFile.close();

        return y;
    }

    // Method generateR generates the first part of the ElGamal signature from the given generator, random value k and modulus
    public BigInteger generateR(BigInteger generator, BigInteger k, BigInteger modulus) {

        BigInteger r = generator.modPow(k, modulus);
        return r;

    }

    public BigInteger calculateInverse(BigInteger val, BigInteger modulus) {

        // System.out.println("Calculating GCD for Inverse");
        BigInteger t = calculateGCD(val, modulus);
        BigInteger inv = Helper(val, modulus)[0];
        
        if (!t.equals(BigInteger.ONE)) {
            throw new ArithmeticException("Inverse doesn't exist");
        }

        if (inv.compareTo(BigInteger.ZERO) > 0) {
            return inv;
        }

        else {
            return inv.add(modulus);
        }
    }

    public BigInteger calculateGCD(BigInteger val1, BigInteger val2) {

        if (val1.compareTo(val2) < 0) {
            return calculateGCD(val2, val1);
        }
        else if ((val1.mod(val2)).equals(BigInteger.ZERO)) {
            return val2;
        }
        else {
            return calculateGCD(val2, val1.mod(val2));
        }

    }

    public BigInteger[] Helper(BigInteger val1, BigInteger val2) {

        if (val2.equals(BigInteger.ZERO)) {
            return new BigInteger[] {BigInteger.ONE, BigInteger.ZERO};
        }

        BigInteger[] arr = Helper(val2, val1.mod(val2));

        BigInteger a = arr[1];
        BigInteger b = arr[0].subtract((val1.divide(val2)).multiply(arr[1]));

        return new BigInteger[] {a, b};
    }

    public byte[] generateSHA256(byte[] input) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] hash = sha256.digest(input);
            return hash;
        }
        catch(NoSuchAlgorithmException e){
            throw new RuntimeException(e);
        }
    }

}