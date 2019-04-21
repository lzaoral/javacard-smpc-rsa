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

    private static final byte RESET_KEYS = 0x15;

    private static final byte SIGNATURE = 0x20;

    private static final short ARR_LEN = 256;

    private final byte[] tmpBuffer;

    private final Cipher rsa;
    private final RSAPrivateKey key;

    private static byte[] keyStatus;
    private static boolean messageSet = false;

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new RSAClientSign(bArray, bOffset, bLength);
    }

    public RSAClientSign(byte[] buffer, short offset, byte length) {
        tmpBuffer = JCSystem.makeTransientByteArray(ARR_LEN, JCSystem.CLEAR_ON_RESET);

        key = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_2048, false);
        rsa = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);

        keyStatus = new byte[2];

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

            case RESET_KEYS:
                key.clearKey();
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

    private void clearByteArray(byte[] arr) {
        Util.arrayFillNonAtomic(arr, (short) 0, (short) arr.length, (byte) 0);
    }

    private void setNumber(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        short lc = (short) ((short) apduBuffer[ISO7816.OFFSET_LC] & 0xFF);
        byte p2 = apduBuffer[ISO7816.OFFSET_P2];

        if (p2 > 0x01)
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

        short position = (short) (ARR_LEN - (p2 * 0xFF + lc));
        Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, tmpBuffer, position, lc);
    }

    private void updateKey(byte index) {
        if (index != SET_D && index != SET_N)
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);

        ++keyStatus[index];
        if (keyStatus[index] != 2)
            return;

        if (index == SET_D)
            key.setExponent(tmpBuffer, (short) 0, (short) tmpBuffer.length);
        else
            key.setModulus(tmpBuffer, (short) 0, (short) tmpBuffer.length);

        clearByteArray(tmpBuffer);
    }

    private void setRSAKeys(APDU apdu) {
        if (key.isInitialized())
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

        byte[] apduBuffer = apdu.getBuffer();
        short p1 = apduBuffer[ISO7816.OFFSET_P1];

        switch (p1) {
            case SET_D:
                if (keyStatus[SET_D] == 2)
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

                setNumber(apdu);
                updateKey(SET_D);
                break;

            case SET_N:
                if (keyStatus[SET_D] != 2 && keyStatus[SET_N] == 2)
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

                setNumber(apdu);
                updateKey(SET_N);
                break;

            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    private void setMessage(APDU apdu) {
        if (!key.isInitialized())
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

        if (apdu.getBuffer()[ISO7816.OFFSET_P1] != 0)
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

        setNumber(apdu);
        messageSet = true;
    }

    private void signRSAMessage(APDU apdu) {
        if (!key.isInitialized() || !messageSet)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

        byte[] apduBuffer = apdu.getBuffer();

        if (apduBuffer[ISO7816.OFFSET_P1] != 0x00 || apduBuffer[ISO7816.OFFSET_P2] != 0x00)
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

        rsa.init(key, Cipher.MODE_DECRYPT);
        rsa.doFinal(tmpBuffer, (short) 0, (short) tmpBuffer.length, apduBuffer, (short) 0);

        messageSet = false;
        clearByteArray(tmpBuffer);

        apdu.setOutgoingAndSend((short) 0, ARR_LEN);
    }

    public boolean select(boolean b) {
        return true;
    }

    public void deselect(boolean b) {}
}