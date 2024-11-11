package terminal;

import javax.smartcardio.*;
import java.util.List;
import java.util.Scanner;

public class TerminalApp {

    // The APDU command for verifying the PIN
    private static final byte VERIFY_PIN = (byte) 0x20; // Custom INS byte for PIN verification (must match applet's INS byte)

    public static void main(String[] args) {
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

            // Wait for the card to be inserted
            while (!terminal.isCardPresent()) {
                System.out.println("Please insert a card...");
                Thread.sleep(1000); // Wait for 1 second before checking again
            }
            Card card = terminal.connect("*");
            System.out.println("Card connected.");

            // Get the card's channel for communication
            CardChannel channel = card.getBasicChannel();

            // Ask the user for the pin
            System.out.println("Please enter the pin!");
            Scanner in = new Scanner(System.in);
            String pinString = in.nextLine();
            System.out.println("You entered Pin " + pinString);

            /*// Send the PIN verification command to the card
            byte[] pin = pinString.getBytes();
            byte[] commandData = new byte[pin.length + 1];  // First byte is the PIN length
            commandData[0] = (byte) pin.length;
            System.arraycopy(pin, 0, commandData, 1, pin.length);

            CommandAPDU command = new CommandAPDU((byte) 0x00, VERIFY_PIN, (short) 0x00, (short) 0x00, commandData);

            // Send the APDU command and receive the response
            ResponseAPDU response = channel.transmit(command);*/

            // Create a basic APDU command with just the INS byte(0x20)
            byte[] apduCommand = new byte[]{(byte) 0x00, // CLA
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
            }

            // Disconnect the card
            card.disconnect(false);
        } catch (CardException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }
}