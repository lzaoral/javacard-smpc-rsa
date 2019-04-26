package smpc_rsa;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.RSAPrivateKey;

import javacardx.crypto.Cipher;

public class Common {

    /**
     * P2 parameters of received keys and messages
     *
     * Part is only combined with divided data into one byte.
     */
    public static final byte P2_PART_0 = 0x00;
    public static final byte P2_PART_1 = 0x01;
    public static final byte P2_SINGLE = 0x00;
    public static final byte P2_DIVIDED = 0x10;

    /**
     * Constants
     */
    public static final byte DATA_LOADED = 0x20;
    // from JCMathLib
    private static final short DIGIT_MASK = 0xFF;
    private static final short DIGIT_LENGTH = 8;

    /**
     * Copies the data content of the APDU Buffer to the target byte array by parts
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
     * @param target target byte array
     * @param maxAPDULength maximum length of data in APDU buffer
     * @throws ISOException SW_INCORRECT_P1P2
     */
    public static void setNumber(APDU apdu, byte[] target, short maxAPDULength) {
        byte[] apduBuffer = apdu.getBuffer();
        byte p2 = apduBuffer[ISO7816.OFFSET_P2];

        if (p2 != P2_SINGLE && p2 != (P2_DIVIDED | P2_PART_0) && p2 != (P2_DIVIDED | P2_PART_1))
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

        short lc = (short) (apduBuffer[ISO7816.OFFSET_LC] & maxAPDULength);
        // get part number (p2 & 0x0F)
        short position = (short) (target.length - ((p2 & 0x0F) * maxAPDULength + lc));
        javacard.framework.Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, target, position, lc);
    }

    /**
     * Loads the message to the card memory by parts specified
     * in the P2 argument.
     *
     * Upon calling, private key must be initialised, thus exponent and modulus
     * must be already set.
     *
     * After the massage is set, any subsequent call zeroes the stored
     * message and starts its loading from the scratch.
     *
     * @param apdu object representing the communication between the card and the world
     * @param target target byte array
     * @param privateKey RSA private key
     * @param maxAPDULength maximum length of data in APDU buffer
     * @throws ISOException SW_CONDITIONS_NOT_SATISFIED if the keys have not yet
     *     been fully set
     * @throws ISOException SW_INCORRECT_P1P2
     */
    public static byte setMessage(APDU apdu, byte[] target, byte messageState,
                                  RSAPrivateKey privateKey, short maxAPDULength) {
        if (!privateKey.isInitialized())
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

        if (apdu.getBuffer()[ISO7816.OFFSET_P1] != 0x00)
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

        if (messageState == DATA_LOADED) {
            messageState = 0x00;
            clearByteArray(target);
        }

        setNumber(apdu, target, maxAPDULength);
        return updateLoadState(messageState, apdu.getBuffer()[ISO7816.OFFSET_P2]);
    }

    /**
     * Signs the message using RSA and sends the signature to the terminal
     *
     * @param apdu object representing the communication between the card and the world
     * @param message byte array with the message
     * @param messageState byte with the load state of the message
     * @param rsa RSA cipher
     * @throws ISOException SW_CONDITIONS_NOT_SATISFIED if the keys or message
     *     have not yet been fully set
     * @throws ISOException SW_INCORRECT_P1P2
     */
    public static void signMessage(APDU apdu, byte[] message, byte messageState, Cipher rsa) {
        if (messageState != DATA_LOADED)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

        byte[] apduBuffer = apdu.getBuffer();
        checkZeroP1P2(apduBuffer);

        rsa.doFinal(message, (short) 0, (short) message.length, apduBuffer, (short) 0);
        clearByteArray(message);

        apdu.setOutgoingAndSend((short) 0, (short) apduBuffer.length);
    }

    /**
     * Checks that the P1 and P2 bytes ion the apduBuffer are set to; zero
     *
     * @param apduBuffer apduBuffer
     * @throws ISOException SW_INCORRECT_P1P2
     */
    public static void checkZeroP1P2(byte[] apduBuffer) {
        if (apduBuffer[ISO7816.OFFSET_P1] != 0x00 || apduBuffer[ISO7816.OFFSET_P2] != 0x00)
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
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
    public static byte updateLoadState(byte state, byte p2) {
        if (p2 == P2_SINGLE)
            state = DATA_LOADED;

        if (state == p2)
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);

        return state == 0x00 ? p2 : DATA_LOADED;
    }

    /**
     * Zeroes the given array.
     *
     * @param arr array to be zeroed
     */
    public static void clearByteArray(byte[] arr) {
        Util.arrayFillNonAtomic(arr, (short) 0, (short) arr.length, (byte) 0);
    }

    /**
     * Subtract a number from another one stored in a byte array.
     * Function was taken from the JCMathLib library and adapted.
     *
     * @author Vasilios Mavroudis and Petr Svenda
     * @param a byte array
     * @param b byte array
     */
    public static void subtract(byte[] a, byte[] b) {
        short akku = 0;
        short subtraction_result;
        short i = (short) (a.length - 1);
        short j = (short) (b.length - 1);

        for (; i >= 0 && j >= 0; i--, j--) {
            akku = (short) (akku + (short) (b[j] & DIGIT_MASK));
            subtraction_result = (short) ((a[i] & DIGIT_MASK) - (akku & DIGIT_MASK));

            a[i] = (byte) (subtraction_result & DIGIT_MASK);
            akku = (short) ((akku >> DIGIT_LENGTH) & DIGIT_MASK);
            if (subtraction_result < 0) {
                akku++;
            }
        }

        // deal with carry as long as there are digits left in this
        while (i >= 0 && akku != 0) {
            subtraction_result = (short) ((a[i] & DIGIT_MASK) - (akku & DIGIT_MASK));
            a[i] = (byte) (subtraction_result & DIGIT_MASK);
            akku = (short) ((akku >> DIGIT_LENGTH) & DIGIT_MASK);

            if (subtraction_result < 0) {
                akku++;
            }
            i--;
        }
    }
}
