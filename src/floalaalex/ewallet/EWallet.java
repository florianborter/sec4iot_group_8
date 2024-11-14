package floalaalex.ewallet;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;

public class EWallet extends Applet {

    private static final byte[] DEFAULT_PIN = {'1', '2', '3', '4'};
    private static final byte PIN_LENGTH = 4;
    private static final byte MAX_PIN_TRIES = 3;

    private final OwnerPIN pin;

    private static final short CIPHER_LENGTH = 64; //64 since we use RSA-512
    private static final short SIGNATURE_LENGTH = 64; //64 since we use RSA-512

    private final Cipher cipher;

    private final RSAPublicKey cardRsaPublicKey;
    private final RSAPrivateCrtKey cardRsaPrivateKey;

    // Store 4 bytes for IPv4 address
    private static final short IP_ADDRESS_LENGTH = 4;
    private byte[] ipAddress = new byte[IP_ADDRESS_LENGTH];

    // The verification server's public key
    private RSAPublicKey serverRsaPublicKey;

    private static final byte INS_VERIFY_PIN = 0x20;
    private static final byte INS_UPDATE_PIN = 0x21;
    private static final byte INS_SEND_CARD_PUBLIC_KEY = 0x22;
    private static final byte INS_SEND_CARD_PRIVATE_KEY = 0x24;
    private static final byte INS_RECEIVE_SERVER_PUBLIC_KEY = 0x30;
    private static final byte INS_ENCRYPT_AND_SIGN_DATA = 0x32;
    private static final byte INS_SEND_SERVER_PUBLIC_KEY = 0x40;
    private static final byte SET_IP_ADDRESS = (byte) 0x50;
    private static final byte GET_IP_ADDRESS = (byte) 0x52;


    protected EWallet() {
        pin = new OwnerPIN(MAX_PIN_TRIES, PIN_LENGTH);
        pin.update(DEFAULT_PIN, (short) 0, PIN_LENGTH);

        // Variables to store the card's KeyPair
        KeyPair cardRsaKeyPair = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_512);
        cardRsaKeyPair.genKeyPair();
        cardRsaPublicKey = (RSAPublicKey) cardRsaKeyPair.getPublic();
        cardRsaPrivateKey = (RSAPrivateCrtKey) cardRsaKeyPair.getPrivate();

        cipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
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
            case INS_VERIFY_PIN:
                verifyPin(apdu);
                break;
            case INS_UPDATE_PIN:
                requiresUnlockedCard();
                updatePin(apdu);
                break;
            case INS_SEND_CARD_PUBLIC_KEY:
                requiresUnlockedCard();
                sendCardPublicKey(apdu);
                break;
            case INS_SEND_CARD_PRIVATE_KEY:
                requiresUnlockedCard();
                sendCardPrivateKey(apdu);
                break;
            case INS_RECEIVE_SERVER_PUBLIC_KEY:
                requiresUnlockedCard();
                receiveServerPublicKey(apdu);
                break;
            case INS_ENCRYPT_AND_SIGN_DATA:
                requiresUnlockedCard();
                encryptAndSignData(apdu);
                break;
            case INS_SEND_SERVER_PUBLIC_KEY:
                requiresUnlockedCard();
                sendServerPublicKey(apdu);
                break;
            case SET_IP_ADDRESS:
                requiresUnlockedCard();
                setIpAddress(apdu);
                break;
            case GET_IP_ADDRESS:
                requiresUnlockedCard();
                getIpAddress(apdu);
                break;
            default:
                // good practice: If you don't know the INStruction, say so:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void verifyPin(APDU apdu) {
        apdu.setIncomingAndReceive();
        byte[] buffer = apdu.getBuffer();

        if (!pin.check(buffer, ISO7816.OFFSET_CDATA, PIN_LENGTH)) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

    }

    private void updatePin(APDU apdu) {
        requiresUnlockedCard();

        apdu.setIncomingAndReceive();
        byte[] buffer = apdu.getBuffer();

        short length = buffer[ISO7816.OFFSET_LC];
        if (length != PIN_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        pin.update(buffer, ISO7816.OFFSET_CDATA, PIN_LENGTH);
    }

    private void requiresUnlockedCard() {
        if (!pin.isValidated()) {
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

    private void setIpAddress(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();

        // Check if length is 68 bytes: 4 bytes for IP + 64 bytes for signature
        if (dataLen != (IP_ADDRESS_LENGTH + SIGNATURE_LENGTH)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Extract IP address (first 4 bytes) and signature (next 64 bytes)
        byte[] receivedIpAddress = new byte[IP_ADDRESS_LENGTH];
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, receivedIpAddress, (short) 0, IP_ADDRESS_LENGTH);
        byte[] receivedSignature = new byte[SIGNATURE_LENGTH];
        Util.arrayCopy(buffer, (short) (ISO7816.OFFSET_CDATA + IP_ADDRESS_LENGTH), receivedSignature, (short) 0, SIGNATURE_LENGTH);

        // Initialize the signature verification with the server's public key
        Signature signatureVerifier = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
        signatureVerifier.init(serverRsaPublicKey, Signature.MODE_VERIFY);

        // Verify the signature
        boolean isVerified = signatureVerifier.verify(receivedIpAddress, (short) 0, IP_ADDRESS_LENGTH, receivedSignature, (short) 0, SIGNATURE_LENGTH);
        if (!isVerified) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED); // Signature verification failed
        }

        // If signature is valid, store the IP address
        Util.arrayCopy(receivedIpAddress, (short) 0, ipAddress, (short) 0, IP_ADDRESS_LENGTH);
    }


    // Method to retrieve IP address
    private void getIpAddress(APDU apdu) {
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) ipAddress.length);
        apdu.sendBytesLong(ipAddress, (short) 0, (short) ipAddress.length);
    }

}
