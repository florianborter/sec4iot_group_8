package terminal;

import javax.smartcardio.*;

public class TerminalAppTest {
    public static void main(String[] args) {
        byte[] aid = new byte[]{(byte) 0xA0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01, 0x0C, 0x06, 0x01, 0x02};

        try {
            // Initialize card terminal and connect to the card
            TerminalFactory factory = TerminalFactory.getDefault();
            CardTerminal terminal = factory.terminals().list().get(0);
            Card card = terminal.connect("T=0");
            CardChannel channel = card.getBasicChannel();

            selectApplet(channel, aid);

            getDataFromApplet(channel);

            // Send data "1234" to the applet
            sendDataToApplet(channel, "1234");

            // Disconnect the card
            card.disconnect(false);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void selectApplet(CardChannel channel, byte[] aid) throws CardException {
        // Command to select the applet
        /*byte[] selectAppletCommand = {(byte) 0x00, // CLA (Class Byte, 0x00 = standard ISO/IEC 7816-4 command)
                (byte) 0xA4, // (SELECT Command (0xA4): This command is used to select an applet on the smart card. It tells the card that the terminal (reader) wants to switch context to a specific applet identified by the provided AID. Once selected, subsequent commands will be routed to this applet until another SELECT command is issued or the card session is terminated)
                (byte) 0x04, // P1 (P1: This byte specifies the selection method. For example, in the context of the SELECT command. 0x04: Select by AID (Application Identifier).)
                (byte) 0x00, // P2 (P2: This byte specifies further details about the selection... 0x00: Indicates that the first or only occurrence of the specified AID should be selected.)
                (byte) 0x0B, // Length of AID (0x0B = 11 -> 11 Bytes long AID)
                (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x62, (byte) 0x03, (byte) 0x01, (byte) 0x0C, (byte) 0x06, (byte) 0x01, (byte) 0x02 // AID (payload)
        };
        CommandAPDU selectAPDU = new CommandAPDU(selectAppletCommand);*/
        CommandAPDU selectAPDU = new CommandAPDU(
                0x00, // CLA (Class Byte, 0x00 = standard ISO/IEC 7816-4 command)
                0xA4, // INS (SELECT Command (0xA4): This command is used to select an applet on the smart card. It tells the card that the terminal (reader) wants to switch context to a specific applet identified by the provided AID. Once selected, subsequent commands will be routed to this applet until another SELECT command is issued or the card session is terminated)
                0x04, // P1 (P1: This byte specifies the selection method. For example, in the context of the SELECT command. 0x04: Select by AID (Application Identifier).)
                0x00, // P2 (P2: This byte specifies further details about the selection... 0x00: Indicates that the first or only occurrence of the specified AID should be selected.)
                aid // AID (payload)
        );
        ResponseAPDU selectResponse = channel.transmit(selectAPDU);
        System.out.println("Select Applet Response: " + byteArrayToHex(selectResponse.getBytes()));
    }

    private static void getDataFromApplet(CardChannel channel) throws CardException {
        // Command to get data from the applet
        /*In the context of APDU commands, P1 stands for Parameter 1.
          It is one of the two parameter bytes (P1 and P2) that provide additional information or context needed by the instruction specified in the INS byte.
          The values of P1 and P2 can vary depending on the specific instruction (INS) being executed*/
        /*byte[] getDataCommand = {(byte) 0x00, // CLA (0x00 = standard ISO/IEC 7816-4 command)
                (byte) 0x10, // INS (0x10, Get Data -> align this with instructions of applet)
                (byte) 0x00, // P1 (Parameter P1 0x00 for no data)
                (byte) 0x00, // P2
                (byte) 0x01  // LE (Expected length of response)
        };
        CommandAPDU getDataAPDU = new CommandAPDU(getDataCommand);*/
        CommandAPDU getDataAPDU = new CommandAPDU(
                0x00, // CLA (0x00 = standard ISO/IEC 7816-4 command)
                0x10, // INS (0x10, Get Data -> align this with instructions of applet)
                0x00, // P1 (Parameter P1 0x00 for no data)
                0x00, // P2
                0x01 // LE / NE (Expected length of response)
        );
        ResponseAPDU getDataResponse = channel.transmit(getDataAPDU);
        System.out.println("Get Data Response: " + byteArrayToHex(getDataResponse.getBytes()));
    }

    private static void sendDataToApplet(CardChannel channel, String data) throws CardException {
        // Convert the data string to byte array
        byte[] dataBytes = data.getBytes(); // Command to send the data to the applet
        CommandAPDU sendDataAPDU = new CommandAPDU(0x00, // CLA
                0x20, // INS (Check Data instruction)
                0x00, // P1 -> 0x00 Placeholder
                0x00, // P2 -> 0x00 Placeholder
                dataBytes, // Data for command
                0x00, // offset in the data
                dataBytes.length, // LC (length of data)
                0x04); // NE resp. LE (max length of returning data)
        ResponseAPDU sendDataResponse = channel.transmit(sendDataAPDU);
        System.out.println("Send Data Response: " + byteArrayToHex(sendDataResponse.getBytes()));
        System.out.println("SW: " + String.format("%02X%02X", sendDataResponse.getSW1(), sendDataResponse.getSW2()));
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
