package floalaalex.test;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import floalaalex.terminal.Product;
import floalaalex.terminal.VendingMachineApp;

import javax.smartcardio.*;
import java.security.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Scanner;

public class VendingMachineAppTest {

    public static void main(String[] args) throws Exception {

        // Création d'une carte fictive et de son channel
        Card card = new MockCard();
        CardChannel channel = card.getBasicChannel();

        /**
         // Simuler l'envoi d'une commande APDU
         CommandAPDU command = new CommandAPDU(0x00, 0xA4, 0x04, 0x00, new byte[]{0x3F, 0x00});
         ResponseAPDU response = channel.transmit(command);

         // Afficher la réponse simulée
         System.out.println("Réponse APDU : " + new String(response.getData()));

         // Obtenir l'ATR simulé
         ATR atr = card.getATR();
         System.out.println("ATR simulé : " + bytesToHex(atr.getBytes()));
         **/


        /**
        System.out.println("début test");

        // Creation vendingMachineApp
        VendingMachineApp vendingMachineApp = new VendingMachineApp(card);

         List<byte[]> chunksForAPDU = parseProductListTest();
         for (byte[] chunk : chunksForAPDU) {
         System.out.println(new String(chunk));
         }


         String code = askForPinTest();
         System.out.println(code);

        String test = askServerIPAndVerifySignatureTest(channel);
         **/

        rebuildProductsTest();
    }


    public static int MAX_APDU_DATA_SIZE = 256;
    static final byte GET_IP_ADDRESS_INSTRUCTION = (byte) 0x52;
    public static final byte SEND_PRODUCT_DATA_TO_CARD = (byte) 0x60;
    public static final byte SET_IP_ADDRESS_INSTRUCTION = (byte) 0x50;

    // Liste des produits en vente
    static List<Product> products = List.of(
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





    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString().trim();
    }

    public static List<byte[]> parseProductListTest() {

        List<byte[]> chunksForAPDU = new ArrayList<>();
        ObjectMapper objectMapper = new ObjectMapper();
        System.out.println("debug 1");
        String jsonData;

        try {
            jsonData = objectMapper.writeValueAsString(products);
            System.out.println(jsonData);
            System.out.println("debug 2");
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }

        // If the size of the products data is superior to the max size of the data in an APDU, we split the data over multiple APDUs
        if (jsonData.getBytes().length > MAX_APDU_DATA_SIZE) {
            for (int i = 0; i < jsonData.getBytes().length; i += MAX_APDU_DATA_SIZE) {
                int end = Math.min(jsonData.length(), i + MAX_APDU_DATA_SIZE);
                chunksForAPDU.add((jsonData.substring(i, end)).getBytes());
            }
        } else {
            chunksForAPDU.add(jsonData.getBytes());
        }
        return chunksForAPDU;
    }

    public static String askForPinTest(){

        System.out.println("Please enter the card pin");
        Scanner PIN = new Scanner(System.in);
        String codePIN = PIN.nextLine();

        while (!codePIN.matches("\\d{4}")){
            System.out.println("Please enter a valid pin with four numbers from 0-9");
            codePIN = PIN.nextLine();
            System.out.println("vous avez tapé : " + codePIN);
        }

        // Then verify PIN on terminal side
        return codePIN;
    }

    public static String askServerIPAndVerifySignatureTest(CardChannel channel) throws Exception {

        byte[] ip = new byte[] { (byte) 0x4f, (byte) 0x2b, (byte) 0x4b, (byte) 0x2c };

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(512);
        KeyPair serverKeyPair = keyGen.generateKeyPair();
        PrivateKey serverPrivateKey = serverKeyPair.getPrivate();

        byte[] ipSignature = signData(ip, serverPrivateKey);

        byte[] ipWithSignature = new byte[ip.length + ipSignature.length];
        System.arraycopy(ip, 0, ipWithSignature, 0, ip.length);
        System.arraycopy(ipSignature, 0, ipWithSignature, ip.length, ipSignature.length);

        CommandAPDU setIpAddressAPDU = new CommandAPDU(0x00, SET_IP_ADDRESS_INSTRUCTION, 0x00, 0x00, ipWithSignature);
        ResponseAPDU response = channel.transmit(setIpAddressAPDU);

        if (response.getSW() == 0x9000) {
            System.out.println("IP address set successfully.");
        } else {
            System.out.println("Failed to set IP address. SW: " + Integer.toHexString(response.getSW()));
        }

        // test starts here

        CommandAPDU getIpAddressAPDU = new CommandAPDU(0x00, GET_IP_ADDRESS_INSTRUCTION, 0x00, 0x00, 4);
        ResponseAPDU response1 = channel.transmit(getIpAddressAPDU);
        byte[] signatureAndIP;

        if (response1.getSW() == 0x9000) {
            System.out.println("IP address retrieved successfully.");
            signatureAndIP =  response.getData();
        } else {
            System.out.println("Failed to retrieve IP address. SW: " + Integer.toHexString(response.getSW()));
            return null;
        }


        byte[] IPaddress = new byte[4]; // IP address must be 4 bytes for IPv4
        byte[] IPSignature = new byte[4];


        System.arraycopy(signatureAndIP,0,IPaddress,0,4);
        System.arraycopy(signatureAndIP,4,IPSignature,0,4);

        System.out.println(bytesToHex(IPaddress));

        return null;
    }

    public static void rebuildProductsTest() throws JsonProcessingException {

        ObjectMapper objectMapper = new ObjectMapper();
        String json = objectMapper.writeValueAsString(products);
        System.out.println(Objects.equals(products,objectMapper.readValue(json, Product[].class)));
    }




    // FROM CRYPTOX
    public static byte[] signData(byte[] data, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        // Sign the IP address with the server's private key
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }


}

