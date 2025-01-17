package floalaalex.terminal;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

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
    private static final byte CHANGE_PIN_INSTRUCTION = (byte) 0x21;
    private static final byte GET_CARD_PUBLIC_KEY_INSTRUCTION = (byte) 0x22;
    private static final byte GET_CARD_PRIVATE_KEY_INSTRUCTION = (byte) 0x24;
    private static final byte RECEIVE_SERVER_PUBLIC_KEY_INSTRUCTION = (byte) 0x30;
    private static final byte CARD_ENCRYPT_AND_SIGN_DATA_INSTRUCTION = (byte) 0x32;
    private static final byte VALIDATE_TIMESTAMP_INSTRUCTION = (byte) 0x34;
    private static final byte GET_SERVER_PUBLIC_KEY_INSTRUCTION = (byte) 0x40;// Constants for new instructions
    private static final byte SET_IP_ADDRESS_INSTRUCTION = (byte) 0x50;
    static final byte GET_IP_ADDRESS_INSTRUCTION = (byte) 0x52;

    // Vending machine instructions
    public static final byte SEND_PRODUCT_DATA_TO_CARD = (byte) 0x60;
    static final int MAX_APDU_DATA_SIZE = 65535;


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

            //test changing the pin
            //testChangePin(channel);

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

            // Test the chunking
            System.out.println("\n\n\n\nTest encryption and decryption of a bigger text:");
            testOnCardEncryptionChunking(channel, serverPrivateKey, cardPublicKey);

            // Test setting and receiving the IP-Address of the server
            System.out.println("\n\n\n\nTest setting and getting the IP of the server:");
            ipTest(channel, serverPrivateKey);

            // Test the validation of the timestamp (check that timestamp is sent by server)
            System.out.println("\n\n\n\nTest the validation of the timestamp:");
            testTimestamp(channel, serverPrivateKey);


            /**
            // Beginning of VendingMachineApp
            VendingMachineApp vendingMachineApp = new VendingMachineApp(card);

            // Sending the products to the card
            int APDUnumber = vendingMachineApp.sendProducts(card);

            // Checking for IP and signature
            vendingMachineApp.askServerIPAndVerifySignature(cardPublicKey);

            // Card recovering data from the cards
            String productsJSON = rebuildDataFromAPDUs(channel,APDUnumber);

            // Building the List<Product> of products
            List<Product> productList = rebuildProducts(productsJSON);

            // Choosing product
            String productChoice = chooseProduct(productList,channel);
             **/


            // Disconnect the card
            card.disconnect(false);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void testChangePin(CardChannel channel) throws CardException {
        // Test PIN verification
        System.out.println("Please enter the card PIN to verify:");
        Scanner in = new Scanner(System.in);
        String pinString = in.nextLine();
        verifyPin(channel, pinString);

        // Test changing the PIN
        System.out.println("Enter new PIN:");
        String newPin = in.nextLine();
        System.out.println("Confirm new PIN:");
        String confirmPin = in.nextLine();

        if (!newPin.equals(confirmPin)) {
            System.out.println("PINs do not match. PIN change aborted.");
        } else {
            boolean pinChanged = changePin(channel, newPin);
            if (pinChanged) {
                System.out.println("PIN changed successfully.");
            } else {
                System.out.println("PIN change failed.");
            }
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

    private static void ipTest(CardChannel channel, PrivateKey serverPrivateKey) throws Exception {
        // Set an example IP address
        byte[] ipAddress = new byte[]{(byte) 192, (byte) 168, 1, 1};
        sendIpAddress(channel, ipAddress, serverPrivateKey);

        // Retrieve the IP address and print it
        byte[] retrievedIpAddress = retrieveIpAddress(channel);
        if (retrievedIpAddress != null) {
            System.out.println("Retrieved IP address: " + (retrievedIpAddress[0] & 0xFF) + "." + (retrievedIpAddress[1] & 0xFF) + "." + (retrievedIpAddress[2] & 0xFF) + "." + (retrievedIpAddress[3] & 0xFF));
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

    private static boolean changePin(CardChannel channel, String newPin) throws CardException {
        byte[] dataBytes = newPin.getBytes();

        CommandAPDU changePinAPDU = new CommandAPDU(0x00, // CLA
                CHANGE_PIN_INSTRUCTION, // INS (Change PIN instruction)
                0x00, // P1 -> Placeholder
                0x00, // P2 -> Placeholder
                dataBytes, // Data for command
                0x00, // offset in the data
                dataBytes.length, // LC (length of data)
                0x04); // NE resp. LE (max length of returning data)

        ResponseAPDU response = channel.transmit(changePinAPDU);

        // Check the response status word
        if (response.getSW() == 0x9000) {
            return true; // PIN change successful
        } else {
            System.out.println("Error changing PIN. SW: " + Integer.toHexString(response.getSW()));
            return false; // PIN change failed
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

    /**
     * Sends an IP-address to the card. This IP will be signed with the servers private key. The card checks the signature
     *
     * @param channel          channel
     * @param ipAddress        the IP-Address which should be set
     * @param serverPrivateKey the Private key of the server, used for signing
     * @throws Exception exception
     */
    private static void sendIpAddress(CardChannel channel, byte[] ipAddress, PrivateKey serverPrivateKey) throws Exception {
        if (ipAddress.length != 4) {
            throw new IllegalArgumentException("IP address must be 4 bytes for IPv4.");
        }

        byte[] ipSignature = signData(ipAddress, serverPrivateKey);

        // Concatenate IP address and its signature for transmission
        byte[] ipWithSignature = new byte[ipAddress.length + ipSignature.length];
        System.arraycopy(ipAddress, 0, ipWithSignature, 0, ipAddress.length);
        System.arraycopy(ipSignature, 0, ipWithSignature, ipAddress.length, ipSignature.length);

        // Transmit the IP address and its signature
        CommandAPDU setIpAddressAPDU = new CommandAPDU(0x00, SET_IP_ADDRESS_INSTRUCTION, 0x00, 0x00, ipWithSignature);
        ResponseAPDU response = channel.transmit(setIpAddressAPDU);

        // Check response status
        if (response.getSW() == 0x9000) {
            System.out.println("Signed IP address sent to card successfully.");
        } else {
            System.out.println("Failed to send signed IP address. SW: " + Integer.toHexString(response.getSW()));
        }
    }

    private static byte[] retrieveIpAddress(CardChannel channel) throws CardException {
        CommandAPDU getIpAddressAPDU = new CommandAPDU(0x00, GET_IP_ADDRESS_INSTRUCTION, 0x00, 0x00, 4);
        ResponseAPDU response = channel.transmit(getIpAddressAPDU);

        if (response.getSW() == 0x9000) {
            System.out.println("IP address retrieved successfully.");
            return response.getData();
        } else {
            System.out.println("Failed to retrieve IP address. SW: " + Integer.toHexString(response.getSW()));
            return null;
        }
    }

    private static byte[] getCurrentTimestamp() {
        // Get the current time in milliseconds
        long currentTimeMillis = System.currentTimeMillis();

        // Convert milliseconds to seconds (Unix timestamp)
        long timestampInSeconds = currentTimeMillis / 1000;

        // Convert long (64-bit) timestamp to byte array (8 bytes)
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(timestampInSeconds);

        return buffer.array();
    }

    /**
     * Sends a timestamp to the terminal. This timestamp will be signed with the servers private key. The card checks the signature
     *
     * @param channel    channel
     * @param privateKey the Private key of the server, used for signing
     * @throws Exception exception
     */
    private static void testTimestamp(CardChannel channel, PrivateKey privateKey) throws Exception {
        byte[] timestamp = getCurrentTimestamp();
        if (timestamp.length != 8) {
            throw new IllegalArgumentException("IP address must be 4 bytes for IPv4.");
        }

        byte[] signature = signData(timestamp, privateKey);

        // Concatenate the timestamp and its signature for transmission
        byte[] timestampWithSignature = new byte[timestamp.length + signature.length];
        System.arraycopy(timestamp, 0, timestampWithSignature, 0, timestamp.length);
        System.arraycopy(signature, 0, timestampWithSignature, timestamp.length, signature.length);

        // Transmit the IP address and its signature
        CommandAPDU setIpAddressAPDU = new CommandAPDU(0x00, VALIDATE_TIMESTAMP_INSTRUCTION, 0x00, 0x00, timestampWithSignature);
        ResponseAPDU response = channel.transmit(setIpAddressAPDU);

        // Check response status
        if (response.getSW() == 0x9000) {
            System.out.println("Signed timestamp sent to card and validated successfully.");
        } else {
            System.out.println("Failed to send or validate signed timestamp. SW: " + Integer.toHexString(response.getSW()));
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


    /// VedingMachineApp methods defined below ///


    /**
     * This method is used to recover product data sent by the VendingMachineApp to the card. It is used by the "rebuildDataFromAPDUs" defined below
     * @param channel default channel used to communicate with the card
     * @param segmentIndex the index of the APDU sent in case of multiple APDUs
     * @return data from the card in a JSON String format
     * @throws CardException
     */
    public static String recoverProductData(CardChannel channel, int segmentIndex) throws CardException {

        CommandAPDU command = new CommandAPDU(0x00, 0xB0, 0x00, segmentIndex,MAX_APDU_DATA_SIZE);
        ResponseAPDU response = channel.transmit(command);

        if (response.getSW() == 0x9000) {
            byte[] segmentData = response.getData();
            // dataBuilder.append(new String(segmentData));
            return new String(segmentData);
        } else {
            System.out.printf("Erreur : SW=0x%04X%n", response.getSW());
            return null;
        }
    }

    /**
     * This method is used to recover the entire product data sent by the VendingMachineApp to the card.
     * @param channel default channel used to communicate with the card
     * @param APDUs_number is the number of APDU commands used to transmit the product data
     * @return the full product list in a JSON String format
     * @throws CardException
     */
    public static String rebuildDataFromAPDUs(CardChannel channel, int APDUs_number) throws CardException {

        StringBuilder dataBuilder = new StringBuilder();

        for (int i=0;i<APDUs_number;i++){
            dataBuilder.append(recoverProductData(channel,i));
        }

        String completeProductData = dataBuilder.toString();
        System.out.println("Données complètes récupérées sur la carte sous forme de JSON : " + completeProductData);
        return completeProductData;
    }


    /**
     * This method remakes the list of Products from the card data
     * @param JSONdata the product list in a JSON String format
     * @return a list of the Products
     * @throws JsonProcessingException
     */
    public static List<Product> rebuildProducts(String JSONdata) throws JsonProcessingException {

        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.readValue(JSONdata, new TypeReference<List<Product>>() {});
    }


    /**
     * This method selects a product with the user's input and returns the choice to the vending Machine
     * @param productList list of products
     * @param channel default channel used to communicate with the card
     * @return concatenated String of product ID and encrypted product data
     * @throws CardException
     */
    public static String chooseProduct(List<Product> productList, CardChannel channel) throws CardException {

        System.out.println("Please enter the ID of the chosen product (between 1 and 20)");

        Scanner inputSCAN = new Scanner(System.in);
        String productCode = inputSCAN.nextLine();

        while ( !productCode.matches("\\d+") || !(1<=Integer.valueOf(productCode) && Integer.valueOf(productCode)<=20) ){
            System.out.println("Please enter a valid ID of the chosen product (between 1 and 20)");
            productCode = inputSCAN.nextLine();
        }

        int ID = Integer.valueOf(productCode);

        // Converting chosen product info into bytes
        byte[] dataToEncrypt = productList.get(ID).toString().getBytes();
        // Encrypting data on the card
        byte[] encryptedData = encryptDataOnCard(dataToEncrypt, channel);

        String responseToVendingMachine = String.valueOf(ID);

        // We return the productID with the encrypted data
        return responseToVendingMachine + encryptedData.toString();
    }

}