package terminal;

import javax.smartcardio.*;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;

public class TerminalApp {

    // The APDU command for verifying the PIN
    private static final byte VERIFY_PIN = (byte) 0x20; // Custom INS byte for PIN verification (must match applet's INS byte)

    public static void main(String[] args) {
        byte[] aid = new byte[]{(byte) 0xA0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01, 0x0C, 0x06, 0x01, 0x02};

        try {
            // Get the list of available card terminals
            TerminalFactory factory = TerminalFactory.getDefault();
            List<CardTerminal> terminals = factory.terminals().list();

            if (terminals.isEmpty()) {
                System.out.println("No card terminals found.");
                return;
            }

            // Select the first available terminal (modify as necessary)
            CardTerminal terminal = terminals.get(0);
            System.out.println("Using terminal: " + terminal.getName());
            System.out.println("Detecting card... ");

            // Wait for the card to be inserted
            terminal.waitForCardPresent(0); //0 = block indefinitely until card is inserted
            Card card = terminal.connect("*");
            System.out.println("Card connected.");

            // Get the card's channel for communication
            CardChannel channel = card.getBasicChannel();

            // Select the Applet on the Card
            selectApplet(channel, aid);

            // Ask the user for the pin
            /*System.out.println("Please enter the pin!");
            Scanner in = new Scanner(System.in);
            String pinString = in.nextLine();
            System.out.println("You entered Pin " + pinString);*/

            /*// Send the PIN verification command to the card
            byte[] pin = pinString.getBytes();
            byte[] commandData = new byte[pin.length + 1];  // First byte is the PIN length
            commandData[0] = (byte) pin.length;
            System.arraycopy(pin, 0, commandData, 1, pin.length);

            CommandAPDU command = new CommandAPDU((byte) 0x00, VERIFY_PIN, (short) 0x00, (short) 0x00, commandData);

            // Send the APDU command and receive the response
            ResponseAPDU response = channel.transmit(command);*/

            // Create a basic APDU command with just the INS byte(0x20)
            /*byte[] apduCommand = new byte[]{(byte) 0x00, // CLA
                    VERIFY_PIN, // INS
                    (byte) 0x00, // P1
                    (byte) 0x00, // P2
                    (byte) 0x00 // Lc (no data)
            };
            CommandAPDU command = new CommandAPDU(apduCommand); // Send the APDU command and receive the response
            ResponseAPDU response = channel.transmit(command);

            // Check the response status word
            if (response.getSW() == 0x9000) {  // 0x9000 is the success status word
                System.out.println("PIN verification successful.");
            } else {
                System.out.println("PIN verification failed. SW: " + Integer.toHexString(response.getSW()));
            }*/

            // Disconnect the card
            card.disconnect(false);
        } catch (CardException e) {
            e.printStackTrace();
        }
    }

    // Note: if Response: 6A82 is sent in response, check if the applet (AID) is actually available on the card
    private static void selectApplet(CardChannel channel, byte[] aid) throws CardException {
        // Command to select the applet
        CommandAPDU selectAPDU = new CommandAPDU(
                0x00, // CLA (Class Byte, 0x00 = standard ISO/IEC 7816-4 command)
                0xA4, // INS (SELECT Command (0xA4): This command is used to select an applet on the smart card. It tells the card that the terminal (reader) wants to switch context to a specific applet identified by the provided AID. Once selected, subsequent commands will be routed to this applet until another SELECT command is issued or the card session is terminated)
                0x04, // P1 (P1: This byte specifies the selection method. For example, in the context of the SELECT command. 0x04: Select by AID (Application Identifier).)
                0x00, // P2 (P2: This byte specifies further details about the selection... 0x00: Indicates that the first or only occurrence of the specified AID should be selected.)
                aid // AID (payload)
        );
        ResponseAPDU selectResponse = channel.transmit(selectAPDU);
        if (selectResponse.getSW() == 0x9000) {
            System.out.println("Selected applet successfully. Response: " + byteArrayToHex(selectResponse.getBytes()));
        } else {
            System.out.println("Selecting applet failed. Response: " + byteArrayToHex(selectResponse.getBytes()));
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