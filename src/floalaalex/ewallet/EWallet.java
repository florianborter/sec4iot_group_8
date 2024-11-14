package floalaalex.ewallet;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;

public class EWallet extends Applet {

    private static final byte[] PIN = {'1', '2', '3', '4'};
    private static final byte PIN_LENGTH = 4; // Assuming PIN length is 4 digits
    private byte[] pinBuffer = new byte[PIN_LENGTH]; // Buffer to hold PIN sent from floalaalex.terminal
    private boolean cardUnlocked = false;
    private static final short CIPHER_LENGTH = 64; //64 since we use RSA-512
    private static final short SIGNATURE_LENGTH = 64; //64 since we use RSA-512

    private Cipher cipher;

    // Variables to store the card's KeyPair
    private KeyPair cardRsaKeyPair;
    private RSAPublicKey cardRsaPublicKey;
    private RSAPrivateCrtKey cardRsaPrivateKey;

    // The verification server's public key
    private RSAPublicKey serverRsaPublicKey;

    protected EWallet() {
        cardRsaKeyPair = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_512);
        cardRsaKeyPair.genKeyPair();
        cardRsaPublicKey = (RSAPublicKey) cardRsaKeyPair.getPublic();
        cardRsaPrivateKey = (RSAPrivateCrtKey) cardRsaKeyPair.getPrivate();
        cipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false); // Use PKCS1 padding
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new EWallet().register();
    }

    public void process(APDU apdu) {
        // Good practice: Return 9000 on SELECT
        if (selectingApplet()) {
            return;
        }

        byte[] buffer = apdu.getBuffer();
        switch (buffer[ISO7816.OFFSET_INS]) {
            case 0x20:  // Command to verify PIN
                verifyPin(apdu);
                break;
            case 0x22:
                sendCardPublicKey(apdu);
                break;
            case 0x24:
                requiresUnlockedCard();
                sendCardPrivateKey(apdu);
                break;
            case 0x30:
                receiveServerPublicKey(apdu);
                break;
            case 0x32:
                requiresUnlockedCard();
                encryptAndSignData(apdu);
                break;
            case 0x40:
                sendServerPublicKey(apdu);
                break;
            default:
                // good practice: If you don't know the INStruction, say so:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void verifyPin(APDU apdu) {
        apdu.setIncomingAndReceive();
        byte[] buffer = apdu.getBuffer();

        // Ensure that the pin is exactly 4 bytes long
        short length = buffer[ISO7816.OFFSET_LC];
        if (length != PIN_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Copy the payload of the APDU into the buffer
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, pinBuffer, (short) 0, PIN_LENGTH);

        // Check if the pinBuffer (value received from the APDU) is equal to the PIN that is hardcoded on initialization
        if (Util.arrayCompare(pinBuffer, (short) 0, PIN, (short) 0, PIN_LENGTH) != 0) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED); // Pin is incorrect, send corresponding error
        }

        // If PIN is correct unlock card and return success
        unlockAndSendSuccessResponse(apdu);
    }

    private void unlockAndSendSuccessResponse(APDU apdu) {
        cardUnlocked = true;
    }

    private void requiresUnlockedCard() {
        if (!cardUnlocked) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    private void sendCardPublicKey(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        // Retrieve modulus and exponent lengths
        short totalLength = concatenateModulusAndExponent(cardRsaPublicKey, buffer);
        apdu.setOutgoing();
        apdu.setOutgoingLength(totalLength);

        apdu.sendBytesLong(buffer, (short) 0, totalLength);
    }

    private void sendServerPublicKey(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        // Retrieve modulus and exponent lengths
        short totalLength = concatenateModulusAndExponent(serverRsaPublicKey, buffer);
        apdu.setOutgoing();
        apdu.setOutgoingLength(totalLength);

        apdu.sendBytesLong(buffer, (short) 0, totalLength);
    }

    /**
     * This function concatenates the modulus and exponent into the buffer. The size of the modulus is 64 Bytes (using RSA-512)
     *
     * @param cardRsaPublicKey the public key to concatenate
     * @param buffer           the buffer to write the concatenated values into
     * @return the total length of the modulus and exponent in bytes
     */
    private short concatenateModulusAndExponent(RSAPublicKey cardRsaPublicKey, byte[] buffer) {
        short offset = 0;
        // Retrieve modulus and exponent lengths
        short modLength = cardRsaPublicKey.getModulus(buffer, offset);
        offset += modLength;
        short expLength = cardRsaPublicKey.getExponent(buffer, offset);
        // offset += expLength;

        return (short) (modLength + expLength);
    }

    private void sendCardPrivateKey(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        short totalLength = concatenatePQEForTransport(buffer);

        apdu.setOutgoing();
        apdu.setOutgoingLength(totalLength);

        // Send the modulus and exponent back to the terminal
        apdu.sendBytesLong(buffer, (short) 0, totalLength);
    }

    /**
     * Concatenates the P, Q and E in the following format:
     * -------------------------------------------
     * | pLength | P | qLength | Q | eLength | E |
     * -------------------------------------------
     * and writes it into the buffer
     * There is no delimiter used. always 2 bytes are used to indicate the length of P, Q and E
     *
     * @param buffer the Buffer, where the concatenated PQE are written to
     * @return the size of the concatenated
     */
    private short concatenatePQEForTransport(byte[] buffer) {
        short lengthIndicatorSize = 2; // determines the space (in bytes) that is used to indicate the size of p resp. q
        short offset = 0;

        // Retrieve the modulus and private exponent of the private key
        offset += lengthIndicatorSize;
        short pLength = cardRsaPrivateKey.getP(buffer, offset);
        // Put plength in the first two bytes
        buffer[0] = (byte) (pLength >> 8);
        buffer[1] = (byte) pLength;

        offset += pLength;

        offset += lengthIndicatorSize;
        short qLength = cardRsaPrivateKey.getQ(buffer, offset);

        // Put qlength in the corresponding bytes
        buffer[(short) (pLength + lengthIndicatorSize)] = (byte) (qLength >> 8);
        buffer[(short) (pLength + lengthIndicatorSize + 1)] = (byte) qLength;

        offset += qLength;

        offset += lengthIndicatorSize;
        short eLength = cardRsaPublicKey.getExponent(buffer, offset);

        // Put elength in the corresponding bytes
        buffer[(short) (lengthIndicatorSize + pLength + lengthIndicatorSize + qLength)] = (byte) (eLength >> 8);
        buffer[(short) (lengthIndicatorSize + pLength + lengthIndicatorSize + qLength + 1)] = (byte) eLength;

        // Total length of p + q + e + (three times the length indicator
        return (short) (lengthIndicatorSize + pLength + lengthIndicatorSize + qLength + lengthIndicatorSize + eLength);
    }

    private void receiveServerPublicKey(APDU apdu) {
        apdu.setIncomingAndReceive();
        byte[] buffer = apdu.getBuffer();

        serverRsaPublicKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512, false);

        short modLength = (short) (buffer[ISO7816.OFFSET_CDATA] & 0xFF);
        short expOffset = (short) (ISO7816.OFFSET_CDATA + 1 + modLength);
        short expLength = (short) (buffer[expOffset] & 0xFF);
        serverRsaPublicKey.setModulus(buffer, (short) (ISO7816.OFFSET_CDATA + 1), modLength);
        serverRsaPublicKey.setExponent(buffer, (short) (expOffset + 1), expLength);
    }

    private void encryptAndSignData(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short dataLength = apdu.setIncomingAndReceive();
        short dataOffset = ISO7816.OFFSET_CDATA;

        // Initialize the cipher for encryption with the server's public key
        cipher.init(serverRsaPublicKey, Cipher.MODE_ENCRYPT);
        // Encrypt the incoming data
        byte[] encryptedData = new byte[CIPHER_LENGTH];
        short encLength = cipher.doFinal(buffer, dataOffset, dataLength, encryptedData, (short) 0);

        // Initialize the signature object for signing with the card's private key
        Signature signature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
        signature.init(cardRsaPrivateKey, Signature.MODE_SIGN);
        // Sign the encrypted data
        byte[] signatureData = new byte[SIGNATURE_LENGTH];
        short sigLength = signature.sign(encryptedData, (short) 0, encLength, signatureData, (short) 0);

        // Combine the encrypted data and the signature
        byte[] combinedData = new byte[(short) (encLength + sigLength)];
        Util.arrayCopy(encryptedData, (short) 0, combinedData, (short) 0, encLength);
        Util.arrayCopy(signatureData, (short) 0, combinedData, encLength, sigLength);

        // Set the response with the combined encrypted and signed data
        Util.arrayCopy(combinedData, (short) 0, buffer, (short) 0, (short) combinedData.length);
        apdu.setOutgoingAndSend((short) 0, (short) combinedData.length);
    }

}
