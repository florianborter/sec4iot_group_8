package floalaalex.util;

import javax.crypto.Cipher;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

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
}
