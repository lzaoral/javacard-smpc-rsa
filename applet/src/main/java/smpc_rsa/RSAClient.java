package smpc_rsa;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;

import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.RandomData;

import javacardx.crypto.Cipher;

/**
 * The {@link RSAClient} class represents JavaCard applet used
 * for the purpose of client signing.
 *
 * It is recommended to use the provided proxy application
 * to send commands to the given card.
 *
 * @author Lukas Zaoral
 */
public class RSAClient extends Applet {

    private static final byte CLA_RSA_SMPC_CLIENT = (byte) 0x80; // TODO:

    /**
     * Instruction codes
     */
    private static final byte INS_GENERATE_KEYS = 0x10;
    private static final byte INS_GET_KEYS = 0x12;
    private static final byte INS_SET_MESSAGE = 0x14;
    private static final byte INS_SIGNATURE = 0x16;
    private static final byte INS_RESET = 0x18;

    /**
     * P1 parameters of the INS_GET_KEYS instruction
     */
    private static final byte P1_GET_D1_SERVER = 0x00;
    private static final byte P1_GET_N1 = 0x01;

    /**
     * Helper arrays
     */
    private final byte[] E = new byte[]{0x01, 0x00, 0x01};
    private final byte[] tmpBuffer;
    private final byte[] d1ServerBuffer;

    /**
     * Variables holding the state of sent keys and set messages
     */
    private final byte[] keysSent = new byte[2];
    private byte messageState = 0x00;

    /**
     * RSA objects
     */
    private RandomData rng;
    private KeyPair rsaPair;
    private RSAPrivateKey privateKey;
    private RSAPublicKey publicKey;
    private Cipher rsa;

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
     * Constructor of {@link RSAClient} class. Allocates and creates all used objects.
     *
     * Installation parameters
     * @param bArray bArray
     * @param bOffset bOffset
     * @param bLength bLength
     * @throws ISOException with {@link CryptoException} reason
     */
    public RSAClient(byte[] bArray, short bOffset, byte bLength) {
        tmpBuffer = JCSystem.makeTransientByteArray(Common.PARTIAL_MODULUS_BYTE_LENGTH, JCSystem.CLEAR_ON_RESET);
        d1ServerBuffer = JCSystem.makeTransientByteArray(Common.PARTIAL_MODULUS_BYTE_LENGTH, JCSystem.CLEAR_ON_RESET);

        try {
            rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
            rsa = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);

            rsaPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_2048);
            privateKey = (RSAPrivateKey) rsaPair.getPrivate();
            publicKey = (RSAPublicKey) rsaPair.getPublic();
        } catch (CryptoException e) {
            ISOException.throwIt(e.getReason());
        }

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
                Common.clientSignMessage(apdu, tmpBuffer, messageState, rsa);
                messageState = 0x00;
                break;

            case INS_RESET:
                reset(apdu);
                break;

            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    /**
     * Generates the client and server shares of client key and the client partial modulus.
     * If the keys have already been generated, throws an exception. To regenerate them,
     * use the INS_RESET command first and then try again.
     *
     * @param apdu object representing the communication between the card and the world
     * @throws ISOException SW_COMMAND_NOT_ALLOWED if the keys have already been generated
     * @throws ISOException SW_INCORRECT_P1P2
     * @throws ISOException with {@link CryptoException} reason
     */
    private void generateRSAKeys(APDU apdu) {
        if (privateKey.isInitialized() || publicKey.isInitialized())
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);

        Common.checkZeroP1P2(apdu.getBuffer());

        try {
            publicKey.setExponent(E, (short) 0, (short) E.length);

            rsaPair.genKeyPair();
            privateKey.getExponent(d1ServerBuffer, (short) 0);

            do {
                rng.generateData(tmpBuffer, (short) 0, (short) tmpBuffer.length);
            } while (!Common.lessThan(tmpBuffer, d1ServerBuffer));
            Common.subtract(d1ServerBuffer, tmpBuffer);

            privateKey.setExponent(tmpBuffer, (short) 0, (short) tmpBuffer.length);
            rsa.init(privateKey, Cipher.MODE_DECRYPT);
        } catch (CryptoException e) {
            ISOException.throwIt(e.getReason());
        }

        Common.clearByteArray(tmpBuffer);
    }

    /**
     * Sends a client modulus or server share of the client private exponent depending
     * on the P1 argument. The keys must generated first and can be retrieved only once.
     *
     * @param apdu object representing the communication between the card and the world
     * @throws ISOException SW_CONDITIONS_NOT_SATISFIED the keys have not been initialised
     * @throws ISOException SW_COMMAND_NOT_ALLOWED if the given key part has already been retrieved
     * @throws ISOException SW_INCORRECT_P1P2
     */
    private void getRSAKeys(APDU apdu) {
        if (!privateKey.isInitialized() || !publicKey.isInitialized())
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

        byte[] apduBuffer = apdu.getBuffer();

        if (apduBuffer[ISO7816.OFFSET_P2] != 0x00)
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

        byte p1 = apduBuffer[ISO7816.OFFSET_P1];

        switch (p1) {
            case P1_GET_D1_SERVER:
                if (keysSent[p1] == Common.DATA_TRANSFERRED)
                    ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);

                Common.sendNum(apdu, d1ServerBuffer, (short) 0, true);
                keysSent[p1] = Common.DATA_TRANSFERRED;
                break;

            case P1_GET_N1:
                if (keysSent[p1] == Common.DATA_TRANSFERRED)
                    ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);

                privateKey.getModulus(tmpBuffer, (short) 0);
                Common.sendNum(apdu, tmpBuffer, (short) 0, true);
                keysSent[p1] = Common.DATA_TRANSFERRED;
                break;

            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    /**
     * Loads the message to the card memory by parts specified in the P2 argument.
     *
     * Upon calling, the keys must be generated and the server share if the client exponent
     * and client modulus must be already retrieved.
     *
     * @param apdu object representing the communication between the card and the world
     * @throws ISOException SW_CONDITIONS_NOT_SATISFIED if the keys have not been retrieved or generated
     */
    private void setMessage(APDU apdu) {
        if (keysSent[P1_GET_D1_SERVER] != Common.DATA_TRANSFERRED || keysSent[P1_GET_N1] != Common.DATA_TRANSFERRED)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

        messageState = Common.setMessage(apdu, tmpBuffer, messageState, privateKey);
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
        publicKey.clearKey();

        messageState = 0x00;

        Common.clearByteArray(keysSent);
        Common.clearByteArray(d1ServerBuffer);
        Common.clearByteArray(tmpBuffer);
    }

}
