/**
 *
 */
package ewallet;

import javacard.framework.*;

public class EWallet extends Applet {

    private static final byte[] PIN = {'1', '2', '3', '4'};
    private static final byte PIN_LENGTH = 4; // Assuming PIN length is 4 digits
    private byte[] pinBuffer = new byte[PIN_LENGTH]; // Buffer to hold PIN sent from terminal
    private boolean cardUnlocked = false;


    // Install method (called when the applet is installed on the card)
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
            default:
                // good practice: If you don't know the INStruction, say so:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    // Method to verify the PIN sent from the terminal
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
        sendSuccessResponse(apdu);
    }

    private void sendSuccessResponse(APDU apdu) {
        // Prepare the response buffer with the success status word
        byte highByte = (byte) (ISO7816.SW_NO_ERROR >> 8); // High byte (0x90)
        byte lowByte = (byte) (ISO7816.SW_NO_ERROR & 0xFF); // Low byte (0x00)
        apdu.getBuffer()[0] = highByte;
        apdu.getBuffer()[1] = lowByte;

        // Send the success status word (2 bytes) as the response
        apdu.setOutgoingAndSend((short) 0, (short) 2); //offset = 0, length = 2 bytes
    }

    //TODO: Add helper function to check, if card is unlocked and send error if necessary
}
