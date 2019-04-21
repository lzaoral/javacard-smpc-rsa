package applet;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

/**
 * The {@link RSAClientSign} class represents JavaCard Applet
 * used solely for the purpose of signing. RSA keys must be
 * provided by the user prior other use.
 *
 * @author Lukáš Zaoral
 */
public class RSAClientSign extends Applet {

    private static final byte CLA_RSA_CLIENT_SIGN = 0x00;

    /**
     * Instruction codes
     */
    private static final byte INS_SET_KEYS = 0x10;
    private static final byte INS_SET_MESSAGE = 0x12;
    private static final byte INS_RESET = 0x14;
    private static final byte INS_SIGNATURE = 0x16;

    /**
     * P1 parameters of the INS_SET_KEYS instruction
     */
    private static final byte P1_SET_D = 0x00;
    private static final byte P1_SET_N = 0x01;

    private static final short ARR_LEN = 256;

    private final byte[] tmpBuffer;

    private final Cipher rsa;
    private final RSAPrivateKey key;

    /**
     * Variables holding the state of set keys and messages
     */
    private final byte[] keyStatus = new byte[2];
    private boolean messageSet = false;

    /**
     * Creates the instance of this Applet. Used by the JavaCard runtime itself.
     *
     * Installation parameter
     * @param bArray bArray
     * @param bOffset bOffset
     * @param bLength bLength
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new RSAClientSign(bArray, bOffset, bLength);
    }

    public RSAClientSign(byte[] buffer, short offset, byte length) {
        tmpBuffer = JCSystem.makeTransientByteArray(ARR_LEN, JCSystem.CLEAR_ON_RESET);
        key = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE,
                    KeyBuilder.LENGTH_RSA_2048, false);
        rsa = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);

        register();
    }

    /**
     * Helper method. Zeroes the given array.
     *
     * @param arr array to be zeroed
     */
    private void clearByteArray(byte[] arr) {
        Util.arrayFillNonAtomic(arr, (short) 0, (short) arr.length, (byte) 0);
    }

    /**
     * The `main` method of this applet
     *
     * @param apdu object representing the communication between the card and the world
     * @throws ISOException SW_CLA_NOT_SUPPORTED
     * @throws ISOException SW_INS_NOT_SUPPORTED
     */
    public void process(APDU apdu) {
        if (selectingApplet())
            return;

        byte[] apduBuffer = apdu.getBuffer();
        if (apduBuffer[ISO7816.OFFSET_CLA] != CLA_RSA_CLIENT_SIGN)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);

        switch (apduBuffer[ISO7816.OFFSET_INS]) {
            case INS_SET_KEYS:
                setRSAKeys(apdu);
                break;

            case INS_RESET:
                reset(apdu);
                break;

            case INS_SET_MESSAGE:
                setMessage(apdu);
                break;

            case INS_SIGNATURE:
                signRSAMessage(apdu);
                break;

            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    /**
     * Sets the value of private exponent and modulus by segments
     * described by the header in the APDU Buffer. Private key must be
     * set before the public modulus.
     *
     * P1 - specifies the data to be set
     *        - 0x00 - private exponent
     *        - 0x01 - modulus
     *
     * P2 - specifies part to be set
     *    - first nibble decides whether the data has been divided
     *         - 0x0X - no
     *         - 0x1X - yes
     *    - second nibble is the segment number, e.g.
     *         - 0x11 - second part of divided data
     *
     * Keys can be reset only by calling the INS_RESET instruction,
     * after the keys have been fully set.
     *
     * @param apdu object representing the communication between the card and the world
     * @throws ISOException SW_CONDITIONS_NOT_SATISFIED if the keys are already set
     *             or are set in wrong order
     * @throws ISOException SW_INCORRECT_P1P2
     */
    private void setRSAKeys(APDU apdu) {
        if (key.isInitialized())
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

        byte[] apduBuffer = apdu.getBuffer();
        switch (apduBuffer[ISO7816.OFFSET_P1]) {
            case P1_SET_D:
                if (keyStatus[P1_SET_D] == 2)
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

                setNumber(apdu);
                updateKey(apdu);
                break;

            case P1_SET_N:
                if (keyStatus[P1_SET_D] != 2 || keyStatus[P1_SET_N] == 2)
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

                setNumber(apdu);
                updateKey(apdu);
                break;

            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    /**
     * Copies the data content of the APDU Buffer to the on-card buffer by parts
     * defined in the P2 byte of APDU buffer.
     *
     * @param apdu object representing the communication between the card and the world
     * @throws ISOException SW_INCORRECT_P1P2
     */
    private void setNumber(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        short lc = (short) (apduBuffer[ISO7816.OFFSET_LC] & 0xFF);
        byte p2 = apduBuffer[ISO7816.OFFSET_P2];

        if (p2 != 0x00 && p2 != 0x10 && p2 != 0x11)
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

        p2 &= 0x0F;
        short position = (short) (ARR_LEN - (p2 * 0xFF + lc));
        Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, tmpBuffer, position, lc);
    }

    /**
     * Sets the keys and updates the information about their state
     *
     * @param apdu object representing the communication between the card and the world
     * @throws ISOException SW_INCORRECT_P1P2
     */
    private void updateKey(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        byte p1 = apduBuffer[ISO7816.OFFSET_P1];
        byte p2 = apduBuffer[ISO7816.OFFSET_P2];

        if (p1 != P1_SET_D && p1 != P1_SET_N)
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

        if ((p2 & 0xF0) == 0x00)
            keyStatus[p1] = 2;
        else
            ++keyStatus[p1];

        if (keyStatus[p1] != 2)
            return;

        if (p1 == P1_SET_D)
            key.setExponent(tmpBuffer, (short) 0, (short) tmpBuffer.length);
        else
            key.setModulus(tmpBuffer, (short) 0, (short) tmpBuffer.length);

        clearByteArray(tmpBuffer);
    }

    /**
     * Zeroes out all arrays and resets the applet to the initial state.
     *
     * @param apdu object representing the communication between the card and the world
     * @throws ISOException SW_INCORRECT_P1P2
     */
    private void reset(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        if (apduBuffer[ISO7816.OFFSET_P1] != 0x00 || apduBuffer[ISO7816.OFFSET_P2] != 0x00)
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

        key.clearKey();
        messageSet = false;
        clearByteArray(keyStatus);
        clearByteArray(tmpBuffer);
    }

    /**
     * Loads the message to the card memory. The method waits
     * until all segments have been fully sent.
     *
     * Upon calling, private exponent and modulus must be already set.
     *
     * Any subsequent call zeroes the stored message and starts
     * its loading from the scratch.
     *
     * @param apdu object representing the communication between the card and the world
     * @throws ISOException SW_CONDITIONS_NOT_SATISFIED if the keys have not yet been fully set
     * @throws ISOException SW_INCORRECT_P1P2
     */
    private void setMessage(APDU apdu) {
        if (!key.isInitialized())
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

        if (apdu.getBuffer()[ISO7816.OFFSET_P1] != 0x00)
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

        if (messageSet) {
            messageSet = false;
            clearByteArray(tmpBuffer);
        }

        setNumber(apdu);

        byte p2 = apdu.getBuffer()[ISO7816.OFFSET_P2];
        messageSet = p2  == 0x00 || p2 == 0x11;
    }

    /**
     * Signs the message using RSA and sends the signature to the terminal
     *
     * @param apdu object representing the communication between the card and the world
     * @throws ISOException SW_CONDITIONS_NOT_SATISFIED if the keys or message have not yet been fully set
     * @throws ISOException SW_INCORRECT_P1P2
     */
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

}