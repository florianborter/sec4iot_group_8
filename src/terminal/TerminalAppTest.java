package terminal;

import javax.smartcardio.*;

public class TerminalAppTest {
    public static void main(String[] args) {
        try {
            // Initialize card terminal and connect to the card
            TerminalFactory factory = TerminalFactory.getDefault();
            CardTerminal terminal = factory.terminals().list().get(0);
            Card card = terminal.connect("T=0");
            CardChannel channel = card.getBasicChannel();

            selectApplet(channel);

            getDataFromApplet(channel);

            // Send data "1234" to the applet
            sendDataToApplet(channel, "2345");

            // Disconnect the card
            card.disconnect(false);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void selectApplet(CardChannel channel) throws CardException {
        // Command to select the applet
        byte[] selectAppletCommand = {(byte) 0x00, // CLA (Class Byte, 0x00 = standard ISO/IEC 7816-4 command)
                (byte) 0xA4, // (SELECT Command (0xA4): This command is used to select an applet on the smart card. It tells the card that the terminal (reader) wants to switch context to a specific applet identified by the provided AID. Once selected, subsequent commands will be routed to this applet until another SELECT command is issued or the card session is terminated)
                (byte) 0x04, // P1 (P1: This byte specifies the selection method. For example, in the context of the SELECT command. 0x04: Select by AID (Application Identifier).)
                (byte) 0x00, // P2 (P2: This byte specifies further details about the selection... 0x00: Indicates that the first or only occurrence of the specified AID should be selected.)
                (byte) 0x0B, // Length of AID (0x0B = 11 -> 11 Bytes long AID)
                (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x62, (byte) 0x03, (byte) 0x01, (byte) 0x0C, (byte) 0x06, (byte) 0x01, (byte) 0x02 // AID (payload)
        };
        CommandAPDU selectAPDU = new CommandAPDU(selectAppletCommand);
        ResponseAPDU selectResponse = channel.transmit(selectAPDU);
        System.out.println("Select Applet Response: " + byteArrayToHex(selectResponse.getBytes()));
    }

    private static void getDataFromApplet(CardChannel channel) throws CardException {
        // Command to get data from the applet
        byte[] getDataCommand = {(byte) 0x00, // CLA (0x00 = standard ISO/IEC 7816-4 command)
                (byte) 0x10, // INS (0x10, Get Data -> align this with instructions of applet)
                (byte) 0x00, // P1 (Parameter P1 0x00 for no data)
                (byte) 0x00, // P2
                (byte) 0x01  // Le (Expected length of response)
        };
            /*In the context of APDU commands, P1 stands for Parameter 1.
            It is one of the two parameter bytes (P1 and P2) that provide additional information or context needed by the instruction specified in the INS byte.
            The values of P1 and P2 can vary depending on the specific instruction (INS) being executed*/

        CommandAPDU getDataAPDU = new CommandAPDU(getDataCommand);
        ResponseAPDU getDataResponse = channel.transmit(getDataAPDU);
        System.out.println("Get Data Response: " + byteArrayToHex(getDataResponse.getBytes()));
    }

    private static void sendDataToApplet(CardChannel channel, String data) {
        try { // Convert the data string to byte array
            byte[] dataBytes = data.getBytes(); // Command to send the data to the applet
            byte[] sendDataCommand = {(byte) 0x00, // CLA
                    (byte) 0x20, // INS (Check Data)
                    (byte) 0x00, // P1
                    (byte) 0x00, // P2
                    (byte) dataBytes.length, // Lc (Length of data)
                    dataBytes[0], dataBytes[1], dataBytes[2], dataBytes[3] // Data //TODO: Adjust to send N bytes
            };
            CommandAPDU sendDataAPDU = new CommandAPDU(sendDataCommand);
            ResponseAPDU sendDataResponse = channel.transmit(sendDataAPDU);
            System.out.println("Send Data Response: " + byteArrayToHex(sendDataResponse.getBytes()));
            System.out.println("SW: " + String.format("%02X%02X", sendDataResponse.getSW1(), sendDataResponse.getSW2()));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Utility method to convert byte array to hexadecimal string
    private static String byteArrayToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            hexString.append(String.format("%02X", b));
        }
        return hexString.toString();
    }
}
