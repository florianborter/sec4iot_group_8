package floalaalex.test;

import javax.smartcardio.ATR;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.*;

public class MockCard extends Card {
    private CardChannel mockChannel;

    public MockCard() {
        this.mockChannel = new MockCardChannel();
    }

    @Override
    public ATR getATR() {
        // Simule un ATR fictif
        return new ATR(new byte[]{0x3B, 0x65, 0x00, 0x00, 0x20, 0x63, 0x2B});
    }

    @Override
    public String getProtocol() {
        return "";
    }

    @Override
    public CardChannel getBasicChannel() {
        return mockChannel;
    }

    @Override
    public CardChannel openLogicalChannel() throws CardException {
        return null;
    }

    @Override
    public void beginExclusive() {
        // Simule le début d'un accès exclusif (no-op)
    }

    @Override
    public void endExclusive() {
        // Simule la fin d'un accès exclusif (no-op)
    }

    @Override
    public byte[] transmitControlCommand(int controlCode, byte[] command) {
        // Simule une commande de contrôle (retourne des données fictives)
        return new byte[]{(byte) 0x90, 0x00}; // SW1/SW2 success
    }

    @Override
    public void disconnect(boolean reset) {
        // Simule la déconnexion de la carte (no-op)
    }
}
