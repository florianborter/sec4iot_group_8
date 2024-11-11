/**
 *
 */
package ewallet;

import javacard.framework.*;

public class EWalletTest extends Applet {
    // Define an instruction code for getting data
    private static final byte INS_GET_DATA = (byte) 0x10;
    private static final byte INS_CHECK_DATA = (byte) 0x20;
    private static final byte[] EXPECTED_DATA = {'1', '2', '3', '4'};

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new EWalletTest().register();
    }

    public void process(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        if (selectingApplet()) {
            return;
        }
        switch (buffer[ISO7816.OFFSET_INS]) {
            case INS_GET_DATA:
                // Example data to be sent in response
                byte exampleData = (byte) 0x42;
                buffer[0] = exampleData;
                apdu.setOutgoingAndSend((short) 0, (short) 1);
                break;
            case INS_CHECK_DATA:
                apdu.setIncomingAndReceive();
                if (Util.arrayCompare(buffer, ISO7816.OFFSET_CDATA, EXPECTED_DATA, (short) 0, (short) EXPECTED_DATA.length) == 0) {
                    ISOException.throwIt(ISO7816.SW_NO_ERROR); // Success
                } else {
                    ISOException.throwIt(ISO7816.SW_WRONG_DATA); // Error
                }
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }
}
