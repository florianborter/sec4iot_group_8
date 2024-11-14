package floalaalex.terminal;


import javax.smartcardio.*;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

import static floalaalex.util.CryptoUtil.*;

public class TerminalApp {
    // Applet ID
    private static final byte[] aid = new byte[]{(byte) 0xA0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01, 0x0C, 0x06, 0x01, 0x02};

    // The APDU commands
    private static final byte SELECT_APPLET_INSTRUCTION = (byte) 0xA4;
    private static final byte VERIFY_PIN_INSTRUCTION = (byte) 0x20;
    private static final byte GET_CARD_PUBLIC_KEY_INSTRUCTION = (byte) 0x22;
    private static final byte GET_CARD_PRIVATE_KEY_INSTRUCTION = (byte) 0x24;
    private static final byte RECEIVE_SERVER_PUBLIC_KEY_INSTRUCTION = (byte) 0x30;
    private static final byte CARD_ENCRYPT_AND_SIGN_DATA_INSTRUCTION = (byte) 0x32;
    private static final byte GET_SERVER_PUBLIC_KEY_INSTRUCTION = (byte) 0x40;

    private static final short CIPHER_TEXT_LENGTH = 64; //64 since we use RSA-512
    private static final short SIGNATURE_LENGTH = 64; //64 since we use RSA-512

    public static void main(String[] args) {
        try {
            // Generate Server RSA-512 key pair, for testing purpose only
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(512);
            KeyPair serverKeyPair = keyGen.generateKeyPair();
            PublicKey serverPublicKey = serverKeyPair.getPublic();
            PrivateKey serverPrivateKey = serverKeyPair.getPrivate();
            RSAPublicKeySpec pubKeySpec = KeyFactory.getInstance("RSA").getKeySpec(serverPublicKey, RSAPublicKeySpec.class);

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

            // Send the PIN verification command to the card
            verifyPin(channel, pinString);

            // Retrieve private and public key of the card
            PublicKey cardPublicKey = retrieveCardPublicKey(channel);
            PrivateKey cardPrivateKey = retrieveCardPrivateKey(channel);

            // Sample encryption
            System.out.println("\n\n\n\nTest encryption / decryption with card RSA-Pair:");
            String plainText = "Hello, Smart Card!";
            System.out.println("Plaintext: " + plainText);
            // Decrypt with the private key
            String decryptedData = testDecryptData(testEncryptData(plainText, cardPublicKey), cardPrivateKey);
            System.out.println("Decrypted Ciphertext: " + decryptedData);

            // Send the servers public key onto the card
            sendServerPublicKey(channel, pubKeySpec);

            // Get the servers public key from the card to verify if transfer was successful
            System.out.println("\n\n\n\nGet the servers public key from the card to verify if transfer was successful:");
            PublicKey copyServerPublicKey = retrieveServerPublicKey(channel);
            System.out.println("serverPublicKey: " + serverPublicKey);
            System.out.println("receivedServerPublicKey: " + copyServerPublicKey);

            System.out.println("\n\n\n\nNow lets encrypt some data on the card and decrypt it here:");
            // Encrypt some data
            testOnCardEncryption(channel, serverPrivateKey, cardPublicKey);


            System.out.println("\n\n\n\nTest encryption and decryption of a bigger text:");
            testOnCardEncryptionChunking(channel, serverPrivateKey, cardPublicKey);

            // Disconnect the card
            card.disconnect(false);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void testOnCardEncryption(CardChannel channel, PrivateKey serverPrivateKey, PublicKey cardPublicKey) throws Exception {
        String plaintext = "11111111112222222222333333333344444444445555555555666"; // Max 53 bytes (do chunking otherwise)
        System.out.println("Plaintext to encrypt: " + plaintext);
        byte[] dataToEncrypt = plaintext.getBytes();

        byte[] cipherTextAndSignature = encryptDataOnCard(dataToEncrypt, channel);
        System.out.println("Received ciphertext and Signature: " + byteArrayToHex(cipherTextAndSignature));

        // Extract the encrypted data and signature
        byte[] cipherText = new byte[CIPHER_TEXT_LENGTH];
        byte[] signature = new byte[SIGNATURE_LENGTH];
        System.arraycopy(cipherTextAndSignature, 0, cipherText, 0, CIPHER_TEXT_LENGTH);
        System.arraycopy(cipherTextAndSignature, CIPHER_TEXT_LENGTH, signature, 0, SIGNATURE_LENGTH);
        // Decrypt the received encrypted data
        byte[] decryptedCardData = decryptData(cipherText, serverPrivateKey);
        System.out.println("Decrypted Cipher Text: " + new String(decryptedCardData));

        // Verify the signature
        boolean isSignatureValid = verifySignature(cardPublicKey, cipherText, signature);
        System.out.println("Signature valid? " + isSignatureValid);
    }

    private static void testOnCardEncryptionChunking(CardChannel channel, PrivateKey serverPrivateKey, PublicKey cardPublicKey) throws Exception {
        String plaintext = "1111111111222222222233333333334444444444555555555566611111111112222222222333333333344444444445555555555666asdf\nasdf1111111111222222222233333333334444444444555555555566611111111112222222222333333333344444444445555555555666asdf\nasdf"; // Max 53 bytes (do chunking otherwise)
        System.out.println("Plaintext to encrypt: " + plaintext);
        byte[] dataToEncrypt = plaintext.getBytes();

        int chunkSize = 53;
        List<byte[]> encryptedChunks = new ArrayList<>();
        List<byte[]> signatures = new ArrayList<>();

        for (int i = 0; i < dataToEncrypt.length; i += chunkSize) {
            int remaining = dataToEncrypt.length - i;
            int currentChunkSize = Math.min(remaining, chunkSize);

            byte[] chunk = new byte[currentChunkSize];
            System.arraycopy(dataToEncrypt, i, chunk, 0, currentChunkSize);

            byte[] cipherTextAndSignature = encryptDataOnCard(chunk, channel);
            System.out.println("Received ciphertext and Signature for chunk: " + byteArrayToHex(cipherTextAndSignature));

            // Extract the encrypted data and signature
            byte[] cipherText = new byte[CIPHER_TEXT_LENGTH];
            byte[] signature = new byte[SIGNATURE_LENGTH];
            System.arraycopy(cipherTextAndSignature, 0, cipherText, 0, CIPHER_TEXT_LENGTH);
            System.arraycopy(cipherTextAndSignature, CIPHER_TEXT_LENGTH, signature, 0, SIGNATURE_LENGTH);

            encryptedChunks.add(cipherText);
            signatures.add(signature);
        }

        // Decrypt combined ciphertext
        for (byte[] chunk : encryptedChunks) {
            byte[] decryptedCardData = decryptData(chunk, serverPrivateKey);
            System.out.println("Decrypted Cipher Text: " + new String(decryptedCardData));
        }

        for (int i = 0; i < signatures.size(); i++) {
            // Verify combined signature (simplified example, adjust verification process as needed)
            boolean isSignatureValid = verifySignature(cardPublicKey, encryptedChunks.get(i), signatures.get(i));
            System.out.println("Signature valid? " + isSignatureValid);
        }
    }

    private static byte[] encryptDataOnCard(byte[] dataToEncrypt, CardChannel channel) throws CardException {
        CommandAPDU encryptDataAPDU = new CommandAPDU(0x00, // CLA
                CARD_ENCRYPT_AND_SIGN_DATA_INSTRUCTION, // INS (Check Data instruction)
                0x00, // P1 -> 0x00 Placeholder
                0x00, // P2 -> 0x00 Placeholder
                dataToEncrypt, // Data for command
                0x00, // offset in the data
                dataToEncrypt.length, // LC (length of data)
                256); // NE resp. LE (max length of returning data)
        ResponseAPDU encryptedResponse = channel.transmit(encryptDataAPDU);
        return encryptedResponse.getData();
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
        if (response.getSW() == 0x9000) { // 0x9000 is the success status word
            System.out.println("Selected applet successfully. SW: " + Integer.toHexString(response.getSW()));
        } else {
            System.out.println("Selecting applet failed. SW: " + Integer.toHexString(response.getSW()));
            System.exit(0);
        }
    }

    private static void verifyPin(CardChannel channel, String data) throws CardException {
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
        if (response.getSW() != 0x9000) {
            System.out.println("PIN verification failed. SW: " + Integer.toHexString(response.getSW()));
            System.exit(0);
        } else {
            System.out.println("PIN verification successful.");
        }
    }

    private static PublicKey retrieveCardPublicKey(CardChannel channel) throws CardException, NoSuchAlgorithmException, InvalidKeySpecException {
        CommandAPDU command = new CommandAPDU(0x00, // CLA
                GET_CARD_PUBLIC_KEY_INSTRUCTION, // INS
                0x00, // P1
                0x00, // P2
                256); // NE / LE (max response length)
        ResponseAPDU response = channel.transmit(command);

        // Check the response status word
        if (response.getSW() != 0x9000) {
            System.out.println("Could not get cards public key. SW: " + Integer.toHexString(response.getSW()));
            System.exit(0);
        }

        byte[] data = response.getData();
        return getRsaPublicKeyFromData(data);
    }

    private static PrivateKey retrieveCardPrivateKey(CardChannel channel) throws Exception {
        // Command to request P, Q, and e from the card
        CommandAPDU command = new CommandAPDU(0x00, GET_CARD_PRIVATE_KEY_INSTRUCTION, 0x00, 0x00, 256);
        ResponseAPDU response = channel.transmit(command);

        // Check the response status word
        if (response.getSW() != 0x9000) {
            System.out.println("Could not get public key. SW: " + Integer.toHexString(response.getSW()));
            System.exit(0);
        }

        byte[] data = response.getData();
        return parsePrivateKeyFromByteArray(data);
    }

    private static void sendServerPublicKey(CardChannel channel, RSAPublicKeySpec keySpec) throws Exception {
        byte[] modulus = keySpec.getModulus().toByteArray();
        // remove the potential extra sign byte from the toByteArray()
        if (modulus[0] == 0x00 && modulus.length == 65) {
            byte[] tmp = new byte[MODULUS_LENGTH];
            System.arraycopy(modulus, 1, tmp, 0, MODULUS_LENGTH);
            modulus = tmp;
        }
        byte[] exponent = keySpec.getPublicExponent().toByteArray();

        // Create APDU to send the modulus and exponent
        ByteBuffer bb = ByteBuffer.allocate(modulus.length + exponent.length + 4);
        bb.put((byte) modulus.length);
        bb.put(modulus);
        bb.put((byte) exponent.length);
        bb.put(exponent);
        byte[] keyData = bb.array();
        CommandAPDU sendPublicKeyAPDU = new CommandAPDU(0x00, RECEIVE_SERVER_PUBLIC_KEY_INSTRUCTION, 0x00, 0x00, keyData);
        ResponseAPDU response = channel.transmit(sendPublicKeyAPDU);

        // Check the response status word
        if (response.getSW() != 0x9000) {
            System.out.println("Error sending servers public key. SW: " + Integer.toHexString(response.getSW()));
            System.exit(0);
        }
    }


    private static PublicKey retrieveServerPublicKey(CardChannel channel) throws CardException, NoSuchAlgorithmException, InvalidKeySpecException {
        CommandAPDU command = new CommandAPDU(0x00, // CLA
                GET_SERVER_PUBLIC_KEY_INSTRUCTION, // INS
                0x00, // P1
                0x00, // P2
                256); // NE / LE (max response length)
        ResponseAPDU response = channel.transmit(command);

        // Check the response status word
        if (response.getSW() != 0x9000) {
            System.out.println("Could not get servers public key. SW: " + Integer.toHexString(response.getSW()));
            System.exit(0);
        }

        byte[] data = response.getData();
        return getRsaPublicKeyFromData(data);
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