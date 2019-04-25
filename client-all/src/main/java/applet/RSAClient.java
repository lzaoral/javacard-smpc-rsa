package applet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.RandomData;

import javacardx.crypto.Cipher;

/**
 * The {@link RSAClient} class represents JavaCard Applet
 * used solely for the purpose of signing. RSA keys must be
 * provided by the user prior to other use.
 *
 * It is recommended to use the provided jar with CardManager
 * to send commands to given card (or emulator).
 *
 * @author Lukas Zaoral
 */
public class RSAClient extends Applet {
    private static final byte CLA_RSA_SMPC_CLIENT = 0x01;

    /**
     * Instruction codes
     */
    private static final byte INS_GENERATE_KEYS = 0x10;
    private static final byte INS_SET_MESSAGE = 0x12;
    private static final byte INS_GET_KEYS = 0x14;
    private static final byte INS_SIGNATURE = 0x16;

    /**
     * P1 parameters of the INS_GET_KEYS instruction
     */
    private static final byte GET_N = 0x00;
    private static final byte GET_D1_SERVER = 0x01;

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
    // from JCMathLib
    private static final short DIGIT_MASK = 0xff;
    private static final short DIGIT_LENGTH = 8;

    private final static byte[] E = new byte[]{0x01, 0x00, 0x01};
    private final byte[] tmpBuffer;
    private final byte[] d1ServerBuffer;

    /**
     * Variables holding the state of sent keys and set messages
     */
    private static boolean nSent = false;
    private static boolean d1ServerSent = false;
    private byte messageSet = 0x00;
    private static final byte MESSAGE_LOADED = 0x20;

    /**
     * RSA objects
     */
    private final RandomData rng;
    private final Cipher rsa;
    private final KeyPair rsaPair;
    private final RSAPrivateKey privateKey;
    private final RSAPublicKey publicKey;

    /**
     * Creates the instance of this Applet. Used by the JavaCard runtime itself.
     *
     * Installation parameters
     * @param bArray bArray
     * @param bOffset bOffset
     * @param bLength bLength
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new RSAClient(bArray, bOffset, bLength);
    }

    /**
     * Constructor of {@link RSAClient} class. Allocates and created all used objects.
     *
     * Installation parameters
     * @param bArray bArray
     * @param bOffset bOffset
     * @param bLength bLength
     */
    public RSAClient(byte[] bArray, short bOffset, byte bLength) {
        tmpBuffer = JCSystem.makeTransientByteArray(ARR_LEN, JCSystem.CLEAR_ON_RESET);
        d1ServerBuffer = JCSystem.makeTransientByteArray(ARR_LEN, JCSystem.CLEAR_ON_RESET);

        rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        rsa = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);

        rsaPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_2048);
        privateKey = (RSAPrivateKey) rsaPair.getPrivate();
        publicKey = (RSAPublicKey) rsaPair.getPublic();

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

        if (apduBuffer[ISO7816.OFFSET_CLA] != CLA_RSA_SMPC_CLIENT)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);

        switch (apduBuffer[ISO7816.OFFSET_INS]) {
            case INS_GENERATE_KEYS:
                generateRSAKeys(apdu);
                break;

            case INS_GET_KEYS:
                getRSAKeys(apdu);
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
     * Generates the client and server shares of client key and the client modulus.
     * If the keys have already been generated, does nothing. To regenerate them,
     * use the INS_RESET command first and then try again.
     *
     * @param apdu object representing the communication between the card and the world
     * @throws ISOException SW_INCORRECT_P1P2
     */
    private void generateRSAKeys(APDU apdu) {
        if (privateKey.isInitialized())
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);

        byte[] apduBuffer = apdu.getBuffer();

        if (apduBuffer[ISO7816.OFFSET_P1] != 0x00 || apduBuffer[ISO7816.OFFSET_P2] != 0x00)
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

        publicKey.setExponent(E, (short) 0, (short) E.length);
        rsaPair.genKeyPair();

        privateKey.getExponent(d1ServerBuffer, (short) 0);

        // d1Client is one byte shorter to be smaller than phi(n)
        // and computing phi(n) !!on a smart card!! is a madness
        rng.generateData(tmpBuffer, (short) 1, (short) (tmpBuffer.length - 1));
        subtract(d1ServerBuffer, tmpBuffer);

        privateKey.setExponent(tmpBuffer, (short) 0, (short) tmpBuffer.length);

        nSent = false;
        d1ServerSent = false;
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

        publicKey.isInitialized();
        privateKey.clearKey();
        messageSet = 0x00;
        clearByteArray(d1ServerBuffer);
        clearByteArray(tmpBuffer);
    }

    /**
     * Sends a key part selected by the P1 argument. The keys must generated first
     * and can be retrieved only once.
     *
     * @param apdu object representing the communication between the card and the world
     * @throws ISOException SW_CONDITIONS_NOT_SATISFIED the keys have not been
     *     initialised
     * @throws ISOException SW_COMMAND_NOT_ALLOWED if the given has already
     *     been retrieved
     * @throws ISOException SW_INCORRECT_P1P2
     */
    private void getRSAKeys(APDU apdu) {
        if (!privateKey.isInitialized())
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

        byte[] apduBuffer = apdu.getBuffer();

        if (apduBuffer[ISO7816.OFFSET_P2] != 0x00)
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

        switch (apduBuffer[ISO7816.OFFSET_P1]) {
            case GET_N:
                if (nSent)
                    ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);

                privateKey.getExponent(tmpBuffer, (short) 1);
                sendNum(tmpBuffer, apdu);
                nSent = true;
                break;

            case GET_D1_SERVER:
                if (d1ServerSent)
                    ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);

                sendNum(d1ServerBuffer, apdu);
                d1ServerSent = true;
                break;

            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    /**
     * Sends the given array and then clears its contents.
     *
     * @param num array to be sent
     * @param apdu object representing the communication between the card and the world
     */
    private void sendNum(byte[] num,  APDU apdu) {
        Util.arrayCopyNonAtomic(num, (short) 0, apdu.getBuffer(), (short) 0, ARR_LEN);
        clearByteArray(num);

        apdu.setOutgoingAndSend((short) 0, ARR_LEN);
    }

    /**
     * Loads the message to the card memory by parts specified
     * in the P2 argument.
     *
     * Upon calling, keys must be already generated.
     *
     * After the mssage is set, any subsequent call zeroes the stored
     * message and starts its loading from the scratch.
     *
     * @param apdu object representing the communication between the card and the world
     * @throws ISOException SW_CONDITIONS_NOT_SATISFIED if the keys have not yet
     *     been fully set
     * @throws ISOException SW_INCORRECT_P1P2
     * @throws ISOException SW_COMMAND_NOT_ALLOWED if the given message part
     *     is set more than once
     */
    private void setMessage(APDU apdu) {
        if (!privateKey.isInitialized())
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

        if (apdu.getBuffer()[ISO7816.OFFSET_P1] != 0x00)
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

        if (messageSet == MESSAGE_LOADED) {
            messageSet = 0x00;
            clearByteArray(tmpBuffer);
        }

        byte[] apduBuffer = apdu.getBuffer();
        byte p2 = apduBuffer[ISO7816.OFFSET_P2];

        if (p2 != P2_SINGLE && p2 != (P2_DIVIDED | P2_PART_0) && p2 != (P2_DIVIDED | P2_PART_1))
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

        // get part number
        p2 &= 0x0F;
        short lc = (short) (apduBuffer[ISO7816.OFFSET_LC] & MAX_APDU_LENGTH);
        short position = (short) (ARR_LEN - (p2 * MAX_APDU_LENGTH + lc));
        Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, tmpBuffer, position, lc);

        if (p2 == P2_SINGLE)
            messageSet = MESSAGE_LOADED;

        if (messageSet == p2)
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);

        messageSet = messageSet == 0x00 ? p2 : MESSAGE_LOADED;
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
        if (!privateKey.isInitialized() || messageSet != MESSAGE_LOADED)
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
     * Subtract a number from another one stored in a byte array.
     * Function was taken from the JCMathLib library.
     *
     * @author Vasilios Mavroudis and Petr Svenda
     * @param a byte array
     * @param b byte array
     */
    public void subtract(byte[] a, byte[] b) {
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

    /**
     * Helper method. Zeroes the given array.
     *
     * @param arr array to be zeroed
     */
    private void clearByteArray(byte[] arr) {
        Util.arrayFillNonAtomic(arr, (short) 0, (short) arr.length, (byte) 0);
    }

}
