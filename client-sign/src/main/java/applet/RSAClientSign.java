package applet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

import javacard.security.KeyBuilder;
import javacard.security.RSAPrivateKey;

import javacardx.crypto.Cipher;

/**
 * The {@link RSAClientSign} class represents JavaCard Applet
 * used solely for the purpose of signing. RSA keys must be
 * provided by the user prior to other use.
 *
 * It is recommended to use the provided jar with CardManager
 * to send commands to given card (or emulator).
 *
 * @author Lukas Zaoral
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
    private static final byte P1_SET_D1_CLIENT = 0x00;
    private static final byte P1_SET_N = 0x01;

    /**
     * P2 parameters of received keys and messages
     *
     * Part is only combined with divided data into one byte.
     */
    private static final byte P2_PART_0 = 0x00;
    private static final byte P2_PART_1 = 0x01;
    private static final byte P2_SINGLE = 0x00;
    private static final byte P2_DIVIDED = 0x10;

    /**
     * Helper constants
     */
    private static final short ARR_LEN = 256;
    private static final short MAX_APDU_LENGTH = 0xFF;

    private final byte[] tmpBuffer;

    /**
     * Variables holding the state of set keys and messages
     */
    private final byte[] keyStatus = new byte[2];
    private static final byte KEY_LOADED = 0x20;
    private byte messageSet = 0x00;

    /**
     * RSA objects
     */
    private final Cipher rsa;
    private final RSAPrivateKey privateKey;

    /**
     * Creates the instance of this Applet. Used by the JavaCard runtime itself.
     *
     * Installation parameters
     * @param bArray bArray
     * @param bOffset bOffset
     * @param bLength bLength
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new RSAClientSign(bArray, bOffset, bLength);
    }

    /**
     * Constructor of {@link RSAClientSign} class. Allocates and created all used objects.
     *
     * Installation parameters
     * @param bArray bArray
     * @param bOffset bOffset
     * @param bLength bLength
     */
    public RSAClientSign(byte[] bArray, short bOffset, byte bLength) {
        tmpBuffer = JCSystem.makeTransientByteArray(ARR_LEN, JCSystem.CLEAR_ON_RESET);
        privateKey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE,
                    KeyBuilder.LENGTH_RSA_2048, false);
        rsa = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);

        register();
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
     * set before the public modulus to be consistent with the demo
     * implementation.
     *
     * P1 - specifies the data to be set
     *        - 0x00 - private exponent
     *        - 0x01 - modulus
     *
     * Keys can be reset only by calling the INS_RESET instruction,
     * after the keys have been fully set.
     *
     * @param apdu object representing the communication between the card and the world
     * @throws ISOException SW_COMMAND_NOT_ALLOWED if the keys are already set
     *     or are set in wrong order
     * @throws ISOException SW_INCORRECT_P1P2
     */
    private void setRSAKeys(APDU apdu) {
        if (privateKey.isInitialized())
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);

        byte[] apduBuffer = apdu.getBuffer();
        switch (apduBuffer[ISO7816.OFFSET_P1]) {
            case P1_SET_D1_CLIENT:
                if (keyStatus[P1_SET_D1_CLIENT] == KEY_LOADED)
                    ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);

                setNumber(apdu);
                updateKey(apdu);
                break;

            case P1_SET_N:
                if (keyStatus[P1_SET_D1_CLIENT] != KEY_LOADED)
                    ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);

                if (keyStatus[P1_SET_N] == KEY_LOADED)
                    ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);

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
     * P2 - specifies part to be set
     *    - first nibble decides whether the data has been divided, e.g.
     *         - 0x00 - no
     *         - 0x1X - yes
     *    - second nibble is the segment number, e.g.
     *         - 0x10 - first part of divided data.
     *         - 0x11 - second part of divided data
     *
     * @param apdu object representing the communication between the card and the world
     * @throws ISOException SW_INCORRECT_P1P2
     */
    private void setNumber(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        byte p2 = apduBuffer[ISO7816.OFFSET_P2];

        if (p2 != P2_SINGLE && p2 != (P2_DIVIDED | P2_PART_0) && p2 != (P2_DIVIDED | P2_PART_1))
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

        short lc = (short) (apduBuffer[ISO7816.OFFSET_LC] & MAX_APDU_LENGTH);
        // get part number (p2 & 0x0F)
        short position = (short) (ARR_LEN - ((p2 & 0x0F) * MAX_APDU_LENGTH + lc));
        Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, tmpBuffer, position, lc);
    }

    /**
     * Sets the keys and updates the information about their state
     *
     * @param apdu object representing the communication between the card and the world
     * @throws ISOException SW_COMMAND_NOT_ALLOWED if the given key part is set more than once
     * @throws ISOException SW_INCORRECT_P1P2
     */
    private void updateKey(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        byte p1 = apduBuffer[ISO7816.OFFSET_P1];
        byte p2 = apduBuffer[ISO7816.OFFSET_P2];

        if (p1 != P1_SET_D1_CLIENT && p1 != P1_SET_N)
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

        keyStatus[p1] = updateLoadState(keyStatus[p1], p2);
        if (keyStatus[p1] != KEY_LOADED)
            return;

        if (p1 == P1_SET_D1_CLIENT)
            privateKey.setExponent(tmpBuffer, (short) 0, (short) tmpBuffer.length);
        else
            privateKey.setModulus(tmpBuffer, (short) 0, (short) tmpBuffer.length);

        clearByteArray(tmpBuffer);
    }

    /**
     * Updates the state byte of given key or message.
     *
     * @param state byte representing the load state of the given key or message
     * @param p2 p2 extracted from the apdu
     * @return update state byte
     * @throws ISOException SW_COMMAND_NOT_ALLOWED if the given key or message
     *     part is set more than once
     */
    private byte updateLoadState(byte state, byte p2) {
        if (p2 == P2_SINGLE)
            state = KEY_LOADED;

        if (state == p2)
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);

        return state == 0x00 ? p2 : KEY_LOADED;
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

        privateKey.clearKey();
        messageSet = 0x00;
        clearByteArray(keyStatus);
        clearByteArray(tmpBuffer);
    }

    /**
     * Loads the message to the card memory by parts specified
     * in the P2 argument.
     *
     * Upon calling, private exponent and modulus must be already set.
     *
     * After the massage is set, any subsequent call zeroes the stored
     * message and starts its loading from the scratch.
     *
     * @param apdu object representing the communication between the card and the world
     * @throws ISOException SW_CONDITIONS_NOT_SATISFIED if the keys have not yet
     *     been fully set
     * @throws ISOException SW_INCORRECT_P1P2
     */
    private void setMessage(APDU apdu) {
        if (!privateKey.isInitialized())
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

        if (apdu.getBuffer()[ISO7816.OFFSET_P1] != 0x00)
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

        if (messageSet == KEY_LOADED) {
            messageSet = 0x00;
            clearByteArray(tmpBuffer);
        }

        setNumber(apdu);
        messageSet = updateLoadState(messageSet, apdu.getBuffer()[ISO7816.OFFSET_P2]);
    }

    /**
     * Signs the message using RSA and sends the signature to the terminal
     *
     * @param apdu object representing the communication between the card and the world
     * @throws ISOException SW_CONDITIONS_NOT_SATISFIED if the keys or message
     *     have not yet been fully set
     * @throws ISOException SW_INCORRECT_P1P2
     */
    private void signRSAMessage(APDU apdu) {
        if (messageSet != KEY_LOADED)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

        byte[] apduBuffer = apdu.getBuffer();

        if (apduBuffer[ISO7816.OFFSET_P1] != 0x00 || apduBuffer[ISO7816.OFFSET_P2] != 0x00)
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

        rsa.init(privateKey, Cipher.MODE_DECRYPT);
        rsa.doFinal(tmpBuffer, (short) 0, (short) tmpBuffer.length, apduBuffer, (short) 0);

        messageSet = 0x00;
        clearByteArray(tmpBuffer);

        apdu.setOutgoingAndSend((short) 0, ARR_LEN);
    }

    /**
     * Zeroes the given array.
     *
     * @param arr array to be zeroed
     */
    private void clearByteArray(byte[] arr) {
        Util.arrayFillNonAtomic(arr, (short) 0, (short) arr.length, (byte) 0);
    }
}
