package applet;

import applet.jcmathlib.*;
import javacard.framework.*;

public class RSAClientSign extends Applet implements MultiSelectable {
    private static final byte RSA_SMPC_CLIENT = 0x1C;

    private static final byte SET_KEYS = 0x10;
    private static final byte SET_E = 0x00; // TODO: may not be needed
    private static final byte SET_D = 0x01;
    private static final byte SET_N = 0x02;

    private static final byte SET_MESSAGE = 0x11;

    private static final byte SIGNATURE = 0x20;

    private static final byte TEST = 0x30;

    private static final short BUFFER_SIZE = 256;

    private final Bignat E;
    private final Bignat D;
    private final Bignat N;

    private final Bignat SGN;

    private static byte[] keyStatus;
    private static boolean generatedKeys = false;
    private static boolean messageSet = false;

    private final ECConfig jcMathCfg;
    private final Bignat_Helper bignatHelper;

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new RSAClientSign(bArray, bOffset, bLength);
    }

    public RSAClientSign(byte[] buffer, short offset, byte length) {
        jcMathCfg = new ECConfig(BUFFER_SIZE);
        bignatHelper = jcMathCfg.bnh;

        E = new Bignat(BUFFER_SIZE, JCSystem.MEMORY_TYPE_PERSISTENT, bignatHelper);
        D = new Bignat(BUFFER_SIZE, JCSystem.MEMORY_TYPE_PERSISTENT, bignatHelper);
        N = new Bignat(BUFFER_SIZE, JCSystem.MEMORY_TYPE_PERSISTENT, bignatHelper);

        SGN = new Bignat(BUFFER_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, bignatHelper);

        keyStatus = JCSystem.makeTransientByteArray((short) 3, JCSystem.CLEAR_ON_RESET);

        register();
    }

    public void process(APDU apdu) {
        if (selectingApplet())
            return;

        byte[] apduBuffer = apdu.getBuffer();

        if (apduBuffer[ISO7816.OFFSET_CLA] != RSA_SMPC_CLIENT)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);

        switch (apduBuffer[ISO7816.OFFSET_INS]) {
            case SET_KEYS:
                setRSAKeys(apdu);
                break;

            case SET_MESSAGE:
                setMessage(apdu);
                break;

            case SIGNATURE:
                signRSAMessage(apdu);
                break;
/*
            case TEST:
                test(apdu);
                break;
*/
            default:
                ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
    }

    private void setNumber(APDU apdu, Bignat num) {
        byte[] apduBuffer = apdu.getBuffer();
        short lc = (short) ((short) apduBuffer[ISO7816.OFFSET_LC] & 0xFF);
        byte p2 = apduBuffer[ISO7816.OFFSET_P2];

        if (p2 > 0x01)
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

        short position = (short) (BUFFER_SIZE - (p2 * 0xFF + lc));
        num.set_from_byte_array(position, apduBuffer, ISO7816.OFFSET_CDATA, lc);
    }

    private void setRSAKeys(APDU apdu) {
        // TODO: reset behavior?

        byte[] apduBuffer = apdu.getBuffer();
        short p1 = apduBuffer[ISO7816.OFFSET_P1];

        switch (p1) {
            case SET_E:
                setNumber(apdu, E);
                break;

            case SET_D:
                setNumber(apdu, D);
                break;

            case SET_N:
                setNumber(apdu, N);
                break;

            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        ++keyStatus[p1];

        // TODO: E length
        if (keyStatus[SET_E] == 1 && keyStatus[SET_D] == 2 && keyStatus[SET_N] == 2) {
            generatedKeys = true;
            E.shrink();
            D.shrink();
            N.shrink();
        }
    }

    private void setMessage(APDU apdu) {
        if (apdu.getBuffer()[ISO7816.OFFSET_P1] != 0)
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

        setNumber(apdu, SGN);

        messageSet = true;
    }

    private void signRSAMessage(APDU apdu) {
        if (!generatedKeys || !messageSet)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

        byte[] apduBuffer = apdu.getBuffer();

        if (apduBuffer[ISO7816.OFFSET_P1] != 0x00 || apduBuffer[ISO7816.OFFSET_P2] != 0x00)
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

        short lc = (short) apduBuffer[ISO7816.OFFSET_LC];

        SGN.from_byte_array(lc, (short) (BUFFER_SIZE - lc), apduBuffer, ISO7816.OFFSET_CDATA);
        SGN.shrink();

        SGN.mod_exp(D, N);

        Util.arrayCopyNonAtomic(SGN.as_byte_array(), (short) 0, apduBuffer, (short) 0, BUFFER_SIZE);
        apdu.setOutgoingAndSend((short) 0, BUFFER_SIZE);
    }

    /*
    private void test(APDU apdu) {
        // Random data
        final byte[] message = {'T', 'h', 'i', 's', ' ', 'i', 's', ' ', 'a', ' ', 't', 'e', 's', 't', '!'};
        Bignat plaintext = new Bignat(BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT, bignatHelper);
        Bignat ciphertext = new Bignat(BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT, bignatHelper);
        plaintext.from_byte_array(message);
        ciphertext.clone(plaintext);

        ciphertext.mod_exp(E, N);
        ciphertext.mod_exp(D, N);

        if (!ciphertext.equals(plaintext))
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    */

    public boolean select(boolean b) {
        return true;
    }

    public void deselect(boolean b) {

    }
}