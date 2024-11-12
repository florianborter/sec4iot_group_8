package ewallet;

import javacard.framework.*;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateCrtKey;
import javacard.security.RSAPublicKey;

public class EWallet extends Applet {

    private static final byte[] PIN = {'1', '2', '3', '4'};
    private static final byte PIN_LENGTH = 4; // Assuming PIN length is 4 digits
    private byte[] pinBuffer = new byte[PIN_LENGTH]; // Buffer to hold PIN sent from terminal
    private boolean cardUnlocked = false;

    // Variables to store the card's KeyPair
    private KeyPair cardRsaKeyPair;
    private RSAPublicKey cardRsaPublicKey;
    private RSAPrivateCrtKey cardRsaPrivateKey;

    protected EWallet() {
        cardRsaKeyPair = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_512);
        cardRsaKeyPair.genKeyPair();
        cardRsaPublicKey = (RSAPublicKey) cardRsaKeyPair.getPublic();
        cardRsaPrivateKey = (RSAPrivateCrtKey) cardRsaKeyPair.getPrivate();
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
        setResponseCode(apdu, ISO7816.SW_NO_ERROR);

        // Send the success status word (2 bytes) as the response
        apdu.setOutgoingAndSend((short) 0, (short) 2); // offset = 0, length = 2 bytes
    }

    private void setResponseCode(APDU apdu, short code) {
        // Prepare the response buffer with the success status word
        byte highByte = (byte) (code >> 8); // High byte (0x90)
        byte lowByte = (byte) (code & 0xFF); // Low byte (0x00)
        apdu.getBuffer()[0] = highByte;
        apdu.getBuffer()[1] = lowByte;
    }

    private void requiresUnlockedCard() {
        if (!cardUnlocked) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    private void sendCardPublicKey(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short offset = 0;

        // Retrieve modulus and exponent lengths
        short modLength = cardRsaPublicKey.getModulus(buffer, offset);
        offset += modLength;
        short expLength = cardRsaPublicKey.getExponent(buffer, offset);
        offset += expLength;

        // Set the outgoing length to the total length of modulus and exponent
        short totalLength = (short) (modLength + expLength);
        apdu.setOutgoing();
        apdu.setOutgoingLength(totalLength);

        apdu.sendBytesLong(buffer, (short) 0, totalLength);
    }

    private void sendCardPrivateKey(APDU apdu) {
        short lengthDiscriminatorSize = 2; // determines the space (in bytes) that is used to indicate the size of p resp. q
        byte[] buffer = apdu.getBuffer();
        short offset = 0;

        // Retrieve the modulus and private exponent of the private key
        offset += lengthDiscriminatorSize;
        short pLength = cardRsaPrivateKey.getP(buffer, offset);
        // Put plength in the first two bytes
        buffer[0] = (byte) (pLength >> 8);
        buffer[1] = (byte) pLength;

        offset += pLength;

        offset += lengthDiscriminatorSize;
        short qLength = cardRsaPrivateKey.getQ(buffer, offset);

        // Put qlength in the corresponding bytes
        buffer[(short) (pLength + lengthDiscriminatorSize)] = (byte) (qLength >> 8);
        buffer[(short) (pLength + lengthDiscriminatorSize + 1)] = (byte) qLength;

        offset += qLength;

        offset += lengthDiscriminatorSize;
        short eLength = cardRsaPublicKey.getExponent(buffer, offset);

        // Put elength in the corresponding bytes
        buffer[(short) (lengthDiscriminatorSize + pLength + lengthDiscriminatorSize + qLength)] = (byte) (eLength >> 8);
        buffer[(short) (lengthDiscriminatorSize + pLength + lengthDiscriminatorSize + qLength + 1)] = (byte) eLength;

        // Total length of modulus + exponent
        short totalLength = (short) (lengthDiscriminatorSize + pLength + lengthDiscriminatorSize + qLength + lengthDiscriminatorSize + eLength);
        apdu.setOutgoing();
        apdu.setOutgoingLength(totalLength);

        // Send the modulus and exponent back to the terminal
        apdu.sendBytesLong(buffer, (short) 0, totalLength);
    }

}
