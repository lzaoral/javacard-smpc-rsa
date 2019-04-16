package applet;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class RSAClientSign extends Applet implements MultiSelectable {
    private static final byte RSA_SMPC_CLIENT = 0x1C;

    private static final byte SET_KEYS = 0x10;
    private static final byte SET_D = 0x00;
    private static final byte SET_N = 0x01;

    private static final byte SET_MESSAGE = 0x11;

    private static final byte SIGNATURE = 0x20;

    private static final short ARR_LEN = 256;

    private final byte[] D;
    private final byte[] N;
    private final byte[] MSG;
    private final byte[] SGN;

    private final Cipher rsa;
    private final RSAPrivateKey key;


    private static byte[] keyStatus;
    private static boolean generatedKeys = false;
    private static boolean messageSet = false;

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new RSAClientSign(bArray, bOffset, bLength);
    }

    public RSAClientSign(byte[] buffer, short offset, byte length) {
        D = new byte[ARR_LEN];
        N = new byte[ARR_LEN];

        MSG = JCSystem.makeTransientByteArray(ARR_LEN, JCSystem.CLEAR_ON_RESET);
        SGN = JCSystem.makeTransientByteArray(ARR_LEN, JCSystem.CLEAR_ON_RESET);

        key = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_2048, false);
        rsa = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);

        keyStatus = JCSystem.makeTransientByteArray((short) 2, JCSystem.CLEAR_ON_RESET);

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

            default:
                ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
    }

    private void setNumber(APDU apdu, byte[] num) {
        byte[] apduBuffer = apdu.getBuffer();
        short lc = (short) ((short) apduBuffer[ISO7816.OFFSET_LC] & 0xFF);
        byte p2 = apduBuffer[ISO7816.OFFSET_P2];

        if (p2 > 0x01)
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

        short position = (short) (ARR_LEN - (p2 * 0xFF + lc));
        Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, num, position, lc);
    }

    private void setRSAKeys(APDU apdu) {
        // TODO: reset behavior?

        byte[] apduBuffer = apdu.getBuffer();
        short p1 = apduBuffer[ISO7816.OFFSET_P1];

        switch (p1) {
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
        if (keyStatus[SET_D] == 2 && keyStatus[SET_N] == 2)
            generatedKeys = true;
    }

    private void setMessage(APDU apdu) {
        if (apdu.getBuffer()[ISO7816.OFFSET_P1] != 0)
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

        setNumber(apdu, MSG);
        messageSet = true;
    }

    private void signRSAMessage(APDU apdu) {
        if (!generatedKeys || !messageSet)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

        byte[] apduBuffer = apdu.getBuffer();

        if (apduBuffer[ISO7816.OFFSET_P1] != 0x00 || apduBuffer[ISO7816.OFFSET_P2] != 0x00)
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

        key.setModulus(N, (short) 0, ARR_LEN);
        key.setExponent(D, (short) 0, ARR_LEN);

        rsa.init(key, Cipher.MODE_DECRYPT);
        rsa.doFinal(MSG, (short) 0, (short) MSG.length, SGN, (short) 0);

        Util.arrayCopyNonAtomic(SGN, (short) 0, apduBuffer, (short) 0, ARR_LEN);
        apdu.setOutgoingAndSend((short) 0, ARR_LEN);
    }

    public boolean select(boolean b) {
        return true;
    }

    public void deselect(boolean b) {}
}