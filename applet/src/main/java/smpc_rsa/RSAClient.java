package smpc_rsa;

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
    private static final byte INS_GET_KEYS = 0x12;
    private static final byte INS_SET_MESSAGE = 0x14;
    private static final byte INS_RESET = 0x16;
    private static final byte INS_SIGNATURE = 0x18;

    /**
     * P1 parameters of the INS_GET_KEYS instruction
     */
    private static final byte P1_GET_N = 0x00;
    private static final byte P1_GET_D1_SERVER = 0x01;

    /**
     * Helper constants
     */
    private static final short ARR_LEN = 256;

    private final static byte[] E = new byte[]{0x01, 0x00, 0x01};
    private final byte[] tmpBuffer;
    private final byte[] d1ServerBuffer;

    /**
     * Variables holding the state of sent keys and set messages
     */
    private static boolean nSent = false;
    private static boolean d1ServerSent = false;
    private byte messageState = 0x00;

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

            case INS_RESET:
                reset(apdu);
                break;

            case INS_SIGNATURE:
                Common.clientSignMessage(apdu, tmpBuffer, messageState, rsa);
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
        Common.checkZeroP1P2(apduBuffer);

        publicKey.setExponent(E, (short) 0, (short) E.length);

        rsaPair.genKeyPair();
        privateKey.getExponent(d1ServerBuffer, (short) 0);

        // d1Client is one byte shorter to be smaller than phi(n)
        // and computing phi(n) !!on a smart card!! is a madness
        rng.generateData(tmpBuffer, (short) 1, (short) (tmpBuffer.length - 1));
        Common.subtract(d1ServerBuffer, tmpBuffer);

        privateKey.setExponent(tmpBuffer, (short) 1, (short) (tmpBuffer.length - 1));
        rsa.init(privateKey, Cipher.MODE_DECRYPT);

        Common.clearByteArray(tmpBuffer);
    }

    /**
     * Zeroes out all arrays and resets the applet to the initial state.
     *
     * @param apdu object representing the communication between the card and the world
     * @throws ISOException SW_INCORRECT_P1P2
     */
    private void reset(APDU apdu) {
        Common.checkZeroP1P2(apdu.getBuffer());

        privateKey.clearKey();

        messageState = 0x00;
        nSent = false;
        d1ServerSent = false;

        Common.clearByteArray(d1ServerBuffer);
        Common.clearByteArray(tmpBuffer);
    }

    /**
     * Sends a client modulus or server share of the client private exponent
     * depending on the P1 argument. The keys must generated first and can
     * be retrieved only once.
     *
     * @param apdu object representing the communication between the card and the world
     * @throws ISOException SW_CONDITIONS_NOT_SATISFIED the keys have not been
     *     initialised
     * @throws ISOException SW_COMMAND_NOT_ALLOWED if the given key part has already
     *     been retrieved
     * @throws ISOException SW_WRONG_LENGTH if the retrieved modulus has got wrong
     *     bit length
     * @throws ISOException SW_INCORRECT_P1P2
     */
    private void getRSAKeys(APDU apdu) {
        if (!privateKey.isInitialized())
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

        byte[] apduBuffer = apdu.getBuffer();

        if (apduBuffer[ISO7816.OFFSET_P2] != 0x00)
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

        switch (apduBuffer[ISO7816.OFFSET_P1]) {
            case P1_GET_N:
                if (nSent)
                    ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);

                if (privateKey.getModulus(tmpBuffer, (short) 0) != ARR_LEN)
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

                Common.sendNum(apdu, tmpBuffer, (short) 0, true);
                nSent = true;
                break;

            case P1_GET_D1_SERVER:
                if (d1ServerSent)
                    ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);

                Common.sendNum(apdu, d1ServerBuffer, (short) 0, true);
                d1ServerSent = true;
                break;

            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    /**
     * Loads the message to the card memory by parts specified
     * in the P2 argument.
     *
     * Upon calling, the keys must be generated and the server share if the client exponent
     * and client modulus must be already retrieved.
     *
     * @param apdu object representing the communication between the card and the world
     * @throws ISOException SW_CONDITIONS_NOT_SATISFIED if the keys have not been retrieved
     *     or generated
     */
    private void setMessage(APDU apdu) {
        if (!d1ServerSent || !nSent)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

        messageState = Common.setMessage(apdu, tmpBuffer, messageState, privateKey);
    }

}
