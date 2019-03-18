package applet;

import javacard.framework.*;
import JCMathlib.jcmathlib.*;

public class MainApplet extends Applet implements MultiSelectable {
    private static final short BUFFER_SIZE = 256;

    
    Bignat e;
    Bignat_Helper bh;
    private byte[] tmpBuffer = JCSystem.makeTransientByteArray(BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT);


    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new MainApplet(bArray, bOffset, bLength);
    }

    public MainApplet(byte[] buffer, short offset, byte length) {
//        bh = Bignat_Helper(BUFFER_SIZE);

//        e = Bignat(BUFFER_SIZE, JCSystem.MEMORY_TYPE_PERSISTENT, );
        register();
    }

    public void process(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        byte cla = apduBuffer[ISO7816.OFFSET_CLA];
        byte ins = apduBuffer[ISO7816.OFFSET_INS];

        short lc = (short) apduBuffer[ISO7816.OFFSET_LC];
        short p1 = (short) apduBuffer[ISO7816.OFFSET_P1];
        short p2 = (short) apduBuffer[ISO7816.OFFSET_P2];

        Util.arrayCopy(tmpBuffer, (short) 0, apduBuffer, (short) 0, BUFFER_SIZE);
        apdu.setOutgoingAndSend((short) 0, BUFFER_SIZE);
    }

    public boolean select(boolean b) {
        return true;
    }

    public void deselect(boolean b) {

    }
}
