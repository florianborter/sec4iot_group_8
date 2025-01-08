package floalaalex.test;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.nio.ByteBuffer;

// Simule un canal de communication
public class MockCardChannel extends CardChannel {
    @Override
    public Card getCard() {
        return new MockCard();
    }

    @Override
    public int getChannelNumber() {
        return 0; // Canal de base
    }

    @Override
    public ResponseAPDU transmit(CommandAPDU command) {
        // Simule une réponse à une commande APDU
        byte[] responseData = "Données simulées".getBytes();
        return new ResponseAPDU(responseData);
    }

    @Override
    public int transmit(ByteBuffer command, ByteBuffer response) {
        // Simule la transmission de données (par buffer)
        String mockResponse = "Réponse fictive";
        response.put(mockResponse.getBytes());
        return mockResponse.length();
    }

    @Override
    public void close() {
        // Simule la fermeture du canal (no-op)
    }
}