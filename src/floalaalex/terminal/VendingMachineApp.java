package floalaalex.terminal;

import javax.smartcardio.*;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import static floalaalex.util.CryptoUtil.*;

import static floalaalex.terminal.TerminalApp.GET_IP_ADDRESS_INSTRUCTION;
import static floalaalex.terminal.TerminalApp.SEND_PRODUCT_DATA_TO_CARD;

public class VendingMachineApp {

    // Taille maximale des données dans une APDU (on commence à 0 dans la boucle for donc 255 et non pas 256)
    final int MAX_APDU_SIZE = 255;
    Card card;
    CardChannel channel;
    String serverIPstring;

    final int MAX_APDU_DATA_SIZE = 65535;
    // Liste des produits en vente
    List<Product> products = List.of(
            new Product(1, "Chocolate Bar", 1.50),
            new Product(2, "Potato Chips", 1.20),
            new Product(3, "Gummy Bears", 1.00),
            new Product(4, "Granola Bar", 1.80),
            new Product(5, "Salted Pretzels", 1.30),
            new Product(6, "Peanuts", 1.00),
            new Product(7, "Trail Mix", 2.00),
            new Product(8, "Muffin", 2.50),
            new Product(9, "Cookies", 1.50),
            new Product(10, "Candy Bar", 1.20),
            new Product(11, "Bottled Water", 1.00),
            new Product(12, "Soda Can", 1.50),
            new Product(13, "Iced Tea", 1.80),
            new Product(14, "Energy Drink", 2.00),
            new Product(15, "Coffee Can", 1.50),
            new Product(16, "Fruit Juice", 1.80),
            new Product(17, "Chewing Gum", 0.80),
            new Product(18, "Mint Candy", 0.90),
            new Product(19, "Popcorn", 1.60),
            new Product(20, "Cup Noodles", 2.50)
    );

    public VendingMachineApp(Card card) {
        this.card = card;
        this.channel = card.getBasicChannel();

        System.out.println("Hello, I am a vending machine app");
    }


    /**
     * This method is going parse the product data to JSON format and then to byte chunks to send to the card via APDUs
     * @param chunksForAPDU is an arrylist provided by the method sendProducts defined below
     */
    public void parseProductList(List<byte[]> chunksForAPDU) {

        try {
            ObjectMapper objectMapper = new ObjectMapper();
            String jsonData = objectMapper.writeValueAsString(products);

            // If the size of the products data is superior to the max size of the data in an APDU, we split the data over multiple APDUs
            if (jsonData.getBytes().length > MAX_APDU_DATA_SIZE) {
                for (int i = 0; i < jsonData.getBytes().length; i += MAX_APDU_DATA_SIZE) {
                    int end = Math.min(jsonData.length(), i + MAX_APDU_DATA_SIZE);
                    chunksForAPDU.add((jsonData.substring(i, end)).getBytes());
                }
            } else {
                chunksForAPDU.add(jsonData.getBytes());
            }

        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * This method is going to send the list of products to the card. It uses the "parseProductList" defined above
     * @param card is the card connected to the vending machine
     * @return returns an integer used by the rebuildDataFromAPDUs method that is necessary to rebuild the data
     * @throws CardException
     */
    public int sendProducts(Card card) throws CardException {

        System.out.println("Sending products to the card");
        List<byte[]> chunksForAPDU = new ArrayList<>();
        parseProductList(chunksForAPDU);

        for (byte[] chunk : chunksForAPDU) {
            CommandAPDU sendDataAPDU = new CommandAPDU(0x00, // CLA
                    SEND_PRODUCT_DATA_TO_CARD, // INS (Check Data instruction)
                    0x00, // P1 -> 0x00 Placeholder
                    0x00, // P2 -> 0x00 Placeholder
                    chunk, // Data for command
                    0x00, // offset in the data
                    chunk.length, // LC (length of data)
                    256); // NE resp. LE (max length of returning data)

            ResponseAPDU response = channel.transmit(sendDataAPDU);

            // Check the response status word
            if (response.getSW() == 0x9000) { // 0x9000 indique succès
                byte[] data = response.getData();
                System.out.println("Segment reçu : " + new String(data));
            }
        }
        return chunksForAPDU.size();
    }


    /**
     * This method gets the server's IP by asking the card. It is used by the "askServerIPAndVerifySignature" method defined below
     * @param channel
     * @return a byte list of IP with the signature
     * @throws CardException
     */
    private static byte[] getServerIpAddress(CardChannel channel) throws CardException {
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

    /**
     * This method is used to ask the card the IP of the verification server and verify the signature. It uses the getServerIpAddress defined above
     * @param retrievedCardPublicKey public card key
     * @return the IP address in form of a string
     * @throws Exception
     */
    public void askServerIPAndVerifySignature(PublicKey retrievedCardPublicKey) throws Exception {

        byte[] signatureAndIP = getServerIpAddress(channel);

        // The IP and the signature have been concatenated so we need to reverse the concatenation

        byte[] IPaddress = new byte[4]; // IP address must be 4 bytes for IPv4
        byte[] IPSignature = new byte[4];

        System.arraycopy(signatureAndIP,0,IPaddress,0,4);
        System.arraycopy(signatureAndIP,4,IPSignature,0,4);

        // Do signature verification
        if (verifySignature(retrievedCardPublicKey,signatureAndIP,IPSignature)){
            serverIPstring = new String(IPaddress);
        } else {
            System.out.println("Failed to verify signature.");
        }
        //serverIPstring = new String(IPaddress);
        //return new String(IPaddress);
    }

    /**
     * This method asks the user to enter the pin code of the card.
     * @return the code pin in a string format to be verified
     */
    public String askForPIN(){

        System.out.println("Please enter the card pin");
        Scanner PIN = new Scanner(System.in);
        String codePIN = PIN.nextLine();

        while (!codePIN.matches("\\d{4}")){
            System.out.println("Please enter a valid pin with four numbers from 0-9");
            codePIN = PIN.nextLine();
        }

        // Then verify PIN on terminal side
        return codePIN;
    }
}
