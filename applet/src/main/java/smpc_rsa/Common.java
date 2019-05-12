package smpc_rsa;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.RSAPrivateKey;

import javacardx.crypto.Cipher;

/**
 * The {@link Common} class represents constants and functionality shared between
 * the SMPC RSA applets.
 *
 * @author Lukas Zaoral
 */
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
    public static final byte DATA_TRANSFERRED = 0x20;
    public static final short PARTIAL_MODULUS_BYTE_LENGTH = 256;
    public static final short MAX_COMMAND_APDU_LENGTH = 255;
    public static final short MAX_RESPONSE_APDU_LENGTH = 256;

    // from JCMathLib
    public static final byte HIGHEST_BIT_MASK = (byte) 0x80;
    private static final byte DIGIT_MASK = (byte) 0xFF;
    private static final byte DIGIT_LENGTH = 8;

    /**
     * Copies the data content of the APDU Buffer to the target byte array by parts
     * defined in the P2 byte of APDU buffer.
     *
     * P2 - specifies part to be set
     *    - first nibble decides whether the data has been divided, e.g.
     *         - 0x00 - no
     *         - 0x1X - yes
     *    - second nibble is the segment order number, e.g.
     *         - 0x10 - first part of divided data.
     *         - 0x11 - second part of divided data
     *
     * @param apdu object representing the communication between the card and the world
     * @param target target byte array
     * @throws ISOException SW_INCORRECT_P1P2
     */
    public static void setNumber(APDU apdu, byte[] target) {
        byte[] apduBuffer = apdu.getBuffer();
        byte p2 = apduBuffer[ISO7816.OFFSET_P2];

        if (p2 != P2_SINGLE && p2 != (P2_DIVIDED | P2_PART_0) && p2 != (P2_DIVIDED | P2_PART_1))
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

        short lc = (short) (apduBuffer[ISO7816.OFFSET_LC] & MAX_COMMAND_APDU_LENGTH);

        // get segment order number (p2 & 0x0F)
        short position = (short) (target.length - ((p2 & 0x0F) * MAX_COMMAND_APDU_LENGTH + lc));
        Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, target, position, lc);
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
     * @param messageState state byte of the message
     * @param privateKey RSA private key
     * @throws ISOException SW_CONDITIONS_NOT_SATISFIED if the keys have not yet been fully set
     * @throws ISOException SW_INCORRECT_P1P2
     */
    public static byte setMessage(APDU apdu, byte[] target, byte messageState, RSAPrivateKey privateKey) {
        if (!privateKey.isInitialized())
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

        if (apdu.getBuffer()[ISO7816.OFFSET_P1] != 0x00)
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

        if (messageState == DATA_TRANSFERRED) {
            messageState = 0x00;
            clearByteArray(target);
        }

        setNumber(apdu, target);
        return updateLoadState(messageState, apdu.getBuffer()[ISO7816.OFFSET_P2]);
    }

    /**
     * Signs the message using RSA and sends the signature to the terminal.
     *
     * @param apdu object representing the communication between the card and the world
     * @param message byte array with the message
     * @param messageState byte with the load state of the message
     * @param rsa RSA cipher
     * @throws ISOException SW_CONDITIONS_NOT_SATISFIED if the keys or message have not yet been fully set
     * @throws ISOException SW_INCORRECT_P1P2
     */
    public static void clientSignMessage(APDU apdu, byte[] message, byte messageState, Cipher rsa) {
        if (messageState != DATA_TRANSFERRED)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

        byte[] apduBuffer = apdu.getBuffer();
        checkZeroP1P2(apduBuffer);

        try {
            rsa.doFinal(message, (short) 0, (short) message.length, apduBuffer, (short) 0);
        } catch (CryptoException e) {
            ISOException.throwIt(e.getReason());
        }

        clearByteArray(message);
        apdu.setOutgoingAndSend((short) 0, (short) message.length);
    }

    /**
     * Checks that the P1 and P2 bytes in the `apduBuffer` are set to zero.
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
     * @return updated state byte
     * @throws ISOException SW_COMMAND_NOT_ALLOWED if the given key or message part is set more than once
     */
    public static byte updateLoadState(byte state, byte p2) {
        if (p2 == P2_SINGLE)
            state = DATA_TRANSFERRED;

        if (state == p2)
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);

        return state == 0x00 ? p2 : DATA_TRANSFERRED;
    }

    /**
     * Sends the given array from given offset and then clears
     * its depending on the `clearAll` parameter contents.
     *
     * The length of sent data depends on the `MAX_RESPONSE_APDU_LENGTH` constant.
     *
     * @param apdu object representing the communication between the card and the world
     * @param num array to be sent
     * @param offset offset to send from
     * @param clearAll decides whether the array will be zeroed
     */
    public static void sendNum(APDU apdu, byte[] num, short offset, boolean clearAll) {
        Util.arrayCopyNonAtomic(num, offset, apdu.getBuffer(), (short) 0, MAX_RESPONSE_APDU_LENGTH);

        if (clearAll)
            Common.clearByteArray(num);

        apdu.setOutgoingAndSend((short) 0, MAX_RESPONSE_APDU_LENGTH);
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
     * @author Vasilios Mavroudis and Petr Svenda, adapted by Lukáš Zaoral
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
