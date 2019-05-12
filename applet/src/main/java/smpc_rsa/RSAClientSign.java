package smpc_rsa;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;

import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import javacard.security.RSAPrivateKey;

import javacardx.crypto.Cipher;

/**
 * The {@link RSAClientSign} class represents JavaCard Applet used solely for
 * the purpose of client signing. The RSA keys must be provided by the user prior
 * to other use.
 *
 * It is recommended to use the provided proxy application to send commands
 * to the given card.
 *
 * @author Lukas Zaoral
 */
public class RSAClientSign extends Applet {

    private static final byte CLA_RSA_CLIENT_SIGN = (byte) 0x80;

    /**
     * Instruction codes
     */
    private static final byte INS_SET_KEYS = 0x10;
    private static final byte INS_SET_MESSAGE = 0x12;
    private static final byte INS_SIGNATURE = 0x14;
    private static final byte INS_RESET = 0x16;

    /**
     * P1 parameters of the INS_SET_KEYS instruction
     */
    private static final byte P1_SET_D1_CLIENT = 0x00;
    private static final byte P1_SET_N1 = 0x01;

    /**
     * Helper arrays
     */
    private final byte[] tmpBuffer;

    /**
     * Variables holding the set keys and messages
     */
    private final byte[] keyState = new byte[2];
    private byte messageState = 0x00;

    /**
     * RSA objects
     */
    private Cipher rsa;
    private RSAPrivateKey privateKey;

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
        tmpBuffer = JCSystem.makeTransientByteArray(Common.PARTIAL_MODULUS_BYTE_LENGTH, JCSystem.CLEAR_ON_RESET);

        try {
            privateKey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE,
                    KeyBuilder.LENGTH_RSA_2048, false);
            rsa = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
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
                messageState = Common.setMessage(apdu, tmpBuffer, messageState, privateKey);
                break;

            case INS_SIGNATURE:
                Common.clientSignMessage(apdu, tmpBuffer, messageState, rsa);
                messageState = 0x00;
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
                if (keyState[P1_SET_D1_CLIENT] == Common.DATA_TRANSFERRED)
                    ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);

                Common.setNumber(apdu, tmpBuffer);
                updateKey(apdu);
                break;

            case P1_SET_N1:
                if (keyState[P1_SET_D1_CLIENT] != Common.DATA_TRANSFERRED)
                    ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);

                if (keyState[P1_SET_N1] == Common.DATA_TRANSFERRED)
                    ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);

                Common.setNumber(apdu, tmpBuffer);
                updateKey(apdu);
                break;

            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }



    /**
     * Sets the keys and updates the information about their state
     *
     * @param apdu object representing the communication between the card and the world
     * @throws ISOException SW_COMMAND_NOT_ALLOWED if the given key part is set more than once
     * @throws ISOException SW_WRONG_LENGTH if the partial modulus n1 is shorter
     * @throws ISOException SW_INCORRECT_P1P2
     */
    private void updateKey(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        byte p1 = apduBuffer[ISO7816.OFFSET_P1];
        byte p2 = apduBuffer[ISO7816.OFFSET_P2];

        if (p1 != P1_SET_D1_CLIENT && p1 != P1_SET_N1)
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

        keyState[p1] = Common.updateLoadState(keyState[p1], p2);
        if (keyState[p1] != Common.DATA_TRANSFERRED)
            return;

        try {
            if (p1 == P1_SET_D1_CLIENT)
                privateKey.setExponent(tmpBuffer, (short) 0, (short) tmpBuffer.length);
            else {
                if ((tmpBuffer[0] & Common.HIGHEST_BIT_MASK) != Common.HIGHEST_BIT_MASK)
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

                privateKey.setModulus(tmpBuffer, (short) 0, (short) tmpBuffer.length);
            }

            if (privateKey.isInitialized())
                rsa.init(privateKey, Cipher.MODE_DECRYPT);
        } catch (CryptoException e) {
            ISOException.throwIt(e.getReason());
        }

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
        Common.clearByteArray(keyState);
        Common.clearByteArray(tmpBuffer);
    }

}
