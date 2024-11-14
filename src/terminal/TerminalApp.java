package terminal;


import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.smartcardio.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
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
    private static final byte RECEIVE_SERVER_PUBLIC_KEY_INSTRUCTION = (byte) 0x30;
    private static final byte CARD_ENCRYPT_DATA_INSTRUCTION = (byte) 0x32;
    private static final byte GET_SERVER_PUBLIC_KEY_INSTRUCTION = (byte) 0x40;

    private static final short statusWordLength = 2; // Two Bytes
    private static final short RSA_512_NUM_BYTES = 64; //64 since we use RSA-512

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

            // Decrypt with the private key
            String decryptedData = decryptData(encryptData(plainText, cardPublicKey), cardPrivateKey);  // cardPrivateKey retrieved from the card
            System.out.println("Decrypted Data: " + decryptedData);


            // Generate RSA-512 key pair
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(512);
            KeyPair serverKeyPair = keyGen.generateKeyPair();
            PublicKey serverPublicKey = serverKeyPair.getPublic();
            PrivateKey serverPrivateKey = serverKeyPair.getPrivate();
            // Get the modulus and exponent
            RSAPublicKeySpec pubKeySpec = KeyFactory.getInstance("RSA").getKeySpec(serverPublicKey, RSAPublicKeySpec.class);
            byte[] serverModulus = pubKeySpec.getModulus().toByteArray();
            // remove the potential extra sign byte from the toByteArray()
            if (serverModulus[0] == 0x00 && serverModulus.length == 65) {
                byte[] tmp = new byte[64];
                System.arraycopy(serverModulus, 1, tmp, 0, 64);
                serverModulus = tmp;
            }
            byte[] serverExponent = pubKeySpec.getPublicExponent().toByteArray();

            sendServerPublicKey(channel, serverModulus, serverExponent);


            System.out.println("test_enc_dec with server pub/priv Key: " + decryptData(encryptData("abcd", serverPublicKey), serverPrivateKey));

            PublicKey copyServerPublicKey = retrieveServerPublicKey(channel);
            System.out.println("copyServerPublicKey: " + copyServerPublicKey);
            System.out.println("serverPublicKey: " + serverPublicKey);

            System.out.println("\n\n\n\nNow lets encrypt some data on the card");
            // Encrypt some data
            byte[] dataToEncrypt = "1234567890".getBytes();
            System.out.println("size: " + dataToEncrypt.length);
            CommandAPDU encryptDataAPDU = new CommandAPDU(
                    0x00, // CLA
                    CARD_ENCRYPT_DATA_INSTRUCTION, // INS (Check Data instruction)
                    0x00, // P1 -> 0x00 Placeholder
                    0x00, // P2 -> 0x00 Placeholder
                    dataToEncrypt, // Data for command
                    0x00, // offset in the data
                    dataToEncrypt.length, // LC (length of data)
                    256); // NE resp. LE (max length of returning data)
            ResponseAPDU encryptedResponse = channel.transmit(encryptDataAPDU);
            System.out.println("SW from encrypt() on card: " + encryptedResponse.getSW());
            byte[] encryptedCardData = encryptedResponse.getData();
            System.out.println("Encrypted Card Data: " + byteArrayToHex(encryptedCardData));
            // Extract the encrypted data and signature
            byte[] encryptedData = new byte[RSA_512_NUM_BYTES];
            byte[] signature = new byte[RSA_512_NUM_BYTES];
            System.arraycopy(encryptedCardData, 0, encryptedData, 0, 64);
            System.arraycopy(encryptedCardData, 64, signature, 0, 64);
            // Decrypt the received encrypted data
            byte[] decryptedCardData = decryptCardData(serverPrivateKey, encryptedData);
            System.out.println("Decrypted Card Data: " + new String(decryptedCardData));

            // Verify the signature
            boolean isSignatureValid = verifySignature(cardPublicKey, encryptedData, signature);
            System.out.println("Signature valid: " + isSignatureValid);

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
                256); // NE / LE (max response length)
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

        int qLength = ((data[pLength + 2] & 0xFF) << 8) | (data[pLength + 2 + 1] & 0xFF);  // Extract qLength (2 bytes)

        int eLength = ((data[2 + pLength + 2 + qLength] & 0xFF) << 8) | (data[2 + pLength + 2 + qLength + 1] & 0xFF);  // Extract qLength (2 bytes)


        System.out.println("plength: " + pLength + " qlength: " + qLength + " eLength: " + eLength);

        // Extract P, Q, E
        int offset = 2;
        BigInteger p = new BigInteger(1, extractComponent(data, offset, pLength));
        offset += pLength;
        offset += 2;
        BigInteger q = new BigInteger(1, extractComponent(data, offset, qLength));
        offset += qLength;
        offset += 2;
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

    private static boolean verifySignature(PublicKey publicKey, byte[] data, byte[] signature) throws Exception {
        Signature sig = Signature.getInstance("SHA1withRSA");
        sig.initVerify(publicKey);
        sig.update(data);
        return sig.verify(signature);
    }

    private static void sendServerPublicKey(CardChannel channel, byte[] modulus, byte[] exponent) throws Exception {
        // Create APDU to send the modulus and exponent
        System.out.println("Modulus length: " + modulus.length);
        System.out.println("Exponent length: " + exponent.length);
        ByteBuffer bb = ByteBuffer.allocate(modulus.length + exponent.length + 4);
        bb.put((byte) modulus.length);
        bb.put(modulus);
        bb.put((byte) exponent.length);
        bb.put(exponent);
        byte[] keyData = bb.array();
        CommandAPDU sendPublicKeyAPDU = new CommandAPDU(0x00, RECEIVE_SERVER_PUBLIC_KEY_INSTRUCTION, 0x00, 0x00, keyData);
        ResponseAPDU response = channel.transmit(sendPublicKeyAPDU);
        System.out.println("Sent Public Key, Response: " + byteArrayToHex(response.getBytes()));

    }


    private static byte[] decryptCardData(PrivateKey privateKey, byte[] encryptedData) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedData);
    }


    private static PublicKey retrieveServerPublicKey(CardChannel channel) throws CardException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
        CommandAPDU command = new CommandAPDU(0x00, // CLA
                GET_SERVER_PUBLIC_KEY_INSTRUCTION, // INS
                0x00, // P1
                0x00, // P2
                256); // NE / LE (max response length)
        ResponseAPDU response = channel.transmit(command);

        if (response.getSW() != 0x9000) {
            System.out.println("retrieveServerPublicKey Could not get public key. SW: " + Integer.toHexString(response.getSW()));
            return null;
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