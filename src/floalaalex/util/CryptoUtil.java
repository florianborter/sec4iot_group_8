package floalaalex.util;

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;

public class CryptoUtil {


    // Encrypt data using RSA public key
    public static byte[] encryptData(String data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding"); // RSA encryption with PKCS1 padding
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data.getBytes());
    }

    // Decrypt data using RSA private key
    public static String decryptData(byte[] data, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding"); // RSA decryption with PKCS1 padding
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(data);
        return new String(decryptedBytes);
    }


    public static byte[] decryptCardData(byte[] encryptedData, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedData);
    }

    public static boolean verifySignature(PublicKey publicKey, byte[] data, byte[] signature) throws Exception {
        Signature sig = Signature.getInstance("SHA1withRSA");
        sig.initVerify(publicKey);
        sig.update(data);
        return sig.verify(signature);
    }

    /**
     * This method is used to parse the Private key from the byte array. The byte array must have the following format:
     * -------------------------------------------
     * | pLength | P | qLength | Q | eLength | E |
     * -------------------------------------------
     * All values must be concatenated without a delimiter
     * where pLength, qLength and eLength must be 2 Bytes long
     *
     * @param data Data in the correct format
     * @return The parsed private key
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static PrivateKey parsePrivateKeyFromByteArray(byte[] data) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // Parse the lengths of P, Q, and e
        int pLength = ((data[0] & 0xFF) << 8) | (data[1] & 0xFF);  // Extract pLength (2 bytes)

        int qLength = ((data[pLength + 2] & 0xFF) << 8) | (data[pLength + 2 + 1] & 0xFF);  // Extract qLength (2 bytes)

        int eLength = ((data[2 + pLength + 2 + qLength] & 0xFF) << 8) | (data[2 + pLength + 2 + qLength + 1] & 0xFF);  // Extract qLength (2 bytes)


        System.out.println("plength: " + pLength + " qlength: " + qLength + " eLength: " + eLength);

        // Extract P, Q, E
        int offset = 2;
        BigInteger p = new BigInteger(1, extractComponent(data, offset, pLength));
        offset += pLength;
        offset += 2;
        BigInteger q = new BigInteger(1, extractComponent(data, offset, qLength));
        offset += qLength;
        offset += 2;
        BigInteger e = new BigInteger(1, extractComponent(data, offset, eLength));

        // Calculate modulus N = P * Q
        BigInteger n = p.multiply(q);

        // Calculate φ(N) = (P - 1)(Q - 1)
        BigInteger phiN = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

        // Calculate private exponent D = e^(-1) mod φ(N)
        BigInteger d = e.modInverse(phiN);

        // Create RSA PrivateKeySpec with N and D
        RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(n, d);

        // Generate the PrivateKey object
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
        return privateKey;
    }

    // Utility method to extract a component from the byte array (Exponent, Modulus, P or Q)
    private static byte[] extractComponent(byte[] data, int offset, int length) {
        byte[] component = new byte[length];
        System.arraycopy(data, offset, component, 0, length);
        return component;
    }
}
