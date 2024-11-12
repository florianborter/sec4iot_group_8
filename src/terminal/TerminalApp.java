package terminal;



import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.smartcardio.*;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Scanner;

public class TerminalApp {
    // Applet ID
    private static final byte[] aid = new byte[]{(byte) 0xA0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01, 0x0C, 0x06, 0x01, 0x02};

    // The APDU commands
    private static final byte SELECT_APPLET_INSTRUCTION = (byte) 0xA4;
    private static final byte VERIFY_PIN_INSTRUCTION = (byte) 0x20;
    private static final byte GET_CARD_PUBLIC_KEY_INSTRUCTION = (byte) 0x22;
    private static final byte GET_CARD_PRIVATE_KEY_INSTRUCTION = (byte) 0x24;

    private static final short statusWordLength = 2; // Two Bytes

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
            System.out.println("Detecting card... ");

            // Wait for the card to be inserted
            terminal.waitForCardPresent(0); //0 = block indefinitely until card is inserted
            Card card = terminal.connect("*");
            System.out.println("Card connected.");

            // Get the card's channel for communication
            CardChannel channel = card.getBasicChannel();

            // Select the Applet on the Card
            selectApplet(channel);


            // Ask the user for the pin
            System.out.println("Please enter the card pin!");
            Scanner in = new Scanner(System.in);
            String pinString = in.nextLine();
            System.out.println("You entered Pin " + pinString);

            // Send the PIN verification command to the card
            verifyPin(channel, pinString);

            /*// Retrieve the Cards public key
            PublicKey cardPublicKey = retrieveCardPublicKey(channel);

            // Retrieve the Cards private key
            PrivateKey cardPrivateKey = retrieveCardPrivateKey(channel);*/

            PublicKey cardPublicKey = retrieveCardPublicKey(channel);
            PrivateKey cardPrivateKey = retrieveCardPrivateKey(channel);


            System.out.println("Now I Test the encryption...");
            // Sample data to encrypt
            String plainText = "Hello, Smart Card!";
            System.out.println("Plaintext to be encrypted: " + plainText);

            // Encrypt with the public key
            byte[] encryptedData = encryptData(plainText, cardPublicKey);  // cardPublicKey retrieved from the card
            System.out.println("Encrypted Data (Base64): " + Base64.getEncoder().encodeToString(encryptedData));

            // Decrypt with the private key
            String decryptedData = decryptData(encryptedData, cardPrivateKey);  // cardPrivateKey retrieved from the card
            System.out.println("Decrypted Data: " + decryptedData);

            // Disconnect the card
            card.disconnect(false);
        } catch (CardException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Note: if Response: 6A82 is sent in response, check if the applet (AID) is actually available on the card
    private static void selectApplet(CardChannel channel) throws CardException {
        // Command to select the applet
        CommandAPDU selectAPDU = new CommandAPDU(0x00, // CLA (Class Byte, 0x00 = standard ISO/IEC 7816-4 command)
                SELECT_APPLET_INSTRUCTION, // INS (SELECT Command (0xA4): This command is used to select an applet on the smart card. It tells the card that the terminal (reader) wants to switch context to a specific applet identified by the provided AID. Once selected, subsequent commands will be routed to this applet until another SELECT command is issued or the card session is terminated)
                0x04, // P1 (P1: This byte specifies the selection method. For example, in the context of the SELECT command. 0x04: Select by AID (Application Identifier).)
                0x00, // P2 (P2: This byte specifies further details about the selection... 0x00: Indicates that the first or only occurrence of the specified AID should be selected.)
                aid // AID (payload)
        );
        ResponseAPDU response = channel.transmit(selectAPDU);
        if (response.getSW() == 0x9000) {
            System.out.println("Selected applet successfully. SW: " + Integer.toHexString(response.getSW()));
        } else {
            System.out.println("Selecting applet failed. SW: " + Integer.toHexString(response.getSW()));
            System.exit(0);
        }
    }

    private static void verifyPin(CardChannel channel, String data) throws CardException {
        // Convert the data string to byte array
        byte[] dataBytes = data.getBytes(); // Command to send the data to the applet
        CommandAPDU sendDataAPDU = new CommandAPDU(0x00, // CLA
                VERIFY_PIN_INSTRUCTION, // INS (Check Data instruction)
                0x00, // P1 -> 0x00 Placeholder
                0x00, // P2 -> 0x00 Placeholder
                dataBytes, // Data for command
                0x00, // offset in the data
                dataBytes.length, // LC (length of data)
                0x04); // NE resp. LE (max length of returning data)
        ResponseAPDU response = channel.transmit(sendDataAPDU);

        // Check the response status word
        if (response.getSW() == 0x9000) {  // 0x9000 is the success status word
            System.out.println("PIN verification successful.");
        } else {
            System.out.println("PIN verification failed. SW: " + Integer.toHexString(response.getSW()));
        }
    }

    private static PublicKey retrieveCardPublicKey(CardChannel channel) throws CardException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
        CommandAPDU command = new CommandAPDU(0x00, // CLA
                GET_CARD_PUBLIC_KEY_INSTRUCTION, // INS
                0x00, // P1
                0x00, // P2
                250); // NE / LE (max response length)
        ResponseAPDU response = channel.transmit(command);
        System.out.println("Get bytes Response: " + byteArrayToHex(response.getBytes()));
        System.out.println("Get data Response: " + byteArrayToHex(response.getData()) + " lenght: " + response.getData().length);
        System.out.println("SW: " + Integer.toHexString(response.getSW()));

        if (response.getSW() != 0x9000) {
            System.out.println("Could not get public key. SW: " + Integer.toHexString(response.getSW()));
            return null;
        }

        byte[] data = response.getData();
        return getRsaPublicKeyFromData(data);
    }

    private static PublicKey getRsaPublicKeyFromData(byte[] data) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // First 64 bytes are modulus since we use RSA-512, remaining are exponent (dynamic length)
        int modulusLength = 64;

        byte[] modulusBytes = Arrays.copyOfRange(data, 0, modulusLength);
        byte[] exponentBytes = Arrays.copyOfRange(data, modulusLength, data.length); // Convert the byte arrays to BigInteger
        java.math.BigInteger modulus = new java.math.BigInteger(1, modulusBytes);
        java.math.BigInteger exponent = new java.math.BigInteger(1, exponentBytes);

        // Create RSA public key spec
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, exponent);
        // Generate the public key
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        System.out.println("Public Key: " + publicKey.toString());
        return publicKey;
    }

    private static PrivateKey retrieveCardPrivateKey(CardChannel channel) throws Exception {
        // Command to request P, Q, and e from the card
        CommandAPDU command = new CommandAPDU(0x00, GET_CARD_PRIVATE_KEY_INSTRUCTION, 0x00, 0x00, 256);
        ResponseAPDU response = channel.transmit(command);

        if (response.getSW() != 0x9000) {
            throw new RuntimeException("Failed to retrieve private key. SW: " + Integer.toHexString(response.getSW()));
        }

        byte[] data = response.getData();
        System.out.println("Get privatekey bytes Response: " + byteArrayToHex(data));

        // Parse the lengths of P, Q, and e
        int pLength = ((data[0] & 0xFF) << 8) | (data[1] & 0xFF);  // Extract pLength (2 bytes)
        int qLength = ((data[2] & 0xFF) << 8) | (data[3] & 0xFF);  // Extract qLength (2 bytes)
        int eLength = ((data[4] & 0xFF) << 8) | (data[5] & 0xFF);  // Extract eLength (2 bytes)

        System.out.println("Elength: " + eLength + "plength: " + pLength + "qlength: " + qLength);

        // Extract P, Q, and e based on their lengths
        int offset = 6; // Skip the first 6 bytes which are lengths
        BigInteger p = new BigInteger(1, extractComponent(data, offset, pLength));
        offset += pLength;
        BigInteger q = new BigInteger(1, extractComponent(data, offset, qLength));
        offset += qLength;
        BigInteger e = new BigInteger(1, extractComponent(data, offset, eLength));

        // Calculate modulus N = P * Q
        BigInteger n = p.multiply(q);

        // Calculate φ(N) = (P - 1)(Q - 1)
        BigInteger phiN = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

        // Calculate private exponent D = e^(-1) mod φ(N)
        BigInteger d = e.modInverse(phiN);

        // Create RSA PrivateKeySpec with N and D
        RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(n, d);

        // Generate the PrivateKey object
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

        return privateKey;
    }


    // Utility method to extract a component from the byte array (Exponent, Modulus, P or Q)
    private static byte[] extractComponent(byte[] data, int offset, int length) {
        byte[] component = new byte[length];
        System.arraycopy(data, offset, component, 0, length);
        return component;
    }

    // Encrypt data using RSA public key
    private static byte[] encryptData(String data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding"); // RSA encryption with PKCS1 padding
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data.getBytes());
    }

    // Decrypt data using RSA private key
    private static String decryptData(byte[] data, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding"); // RSA decryption with PKCS1 padding
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(data);
        return new String(decryptedBytes);
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