/**
 *
 */
package ewallet;

import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.APDU;
import javacard.framework.Util;

public class EWallet extends Applet {

	private static final byte PIN_LENGTH = 4; // Assuming PIN length is 4 digits
    private byte[] storedPin = new byte[PIN_LENGTH];
    private byte[] pinBuffer = new byte[PIN_LENGTH]; // Buffer to hold PIN sent from terminal

	// Constructor for the applet
    protected EWallet(byte[] pin) {
        // Initialize the card with the provided PIN (e.g., by the end-user)
        Util.arrayCopy(pin, (short) 0, storedPin, (short) 0, PIN_LENGTH);
    }

	// Install method (called when the applet is installed on the card)
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        byte[] pin = new byte[PIN_LENGTH];
        Util.arrayCopy(bArray, bOffset, pin, (short) 0, PIN_LENGTH);
        new EWallet(pin).register();
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
        byte[] buffer = apdu.getBuffer();
        short length = buffer[ISO7816.OFFSET_LC];

        if (length != PIN_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, pinBuffer, (short) 0, length);

        // Compare the PIN received with the stored PIN
        if (Util.arrayCompare(pinBuffer, (short) 0, storedPin, (short) 0, PIN_LENGTH) != 0) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        // If PIN is correct, return success
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) 0);  // No data to send back, just verification result
        apdu.sendBytesLong(buffer, (short) 0, (short) 0);
    }
}
