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

public class RSAClient extends Applet {
    private static final byte RSA_SMPC_CLIENT = 0x1C;

    private static final byte GENERATE_KEYS = 0x10;
    private static final byte SET_MESSAGE = 0x11;

    private static final byte GET_KEYS = 0x15;
    private static final byte GET_N = 0x00;
    private static final byte GET_D_SERVER = 0x01;

    private static final byte SIGNATURE = 0x20;

    private static final short ARR_LEN = 256;

    // from JCMathLib
    public static final short digitMask = 0xff;
    public static final short digitLen = 8;

    // E = 65537
    private final static byte[] E = new byte[]{0x01, 0x00, 0x01};

    private final byte[] tmpBuffer;

    private static boolean messageSet = false;

    private static boolean nSent = false;
    private static boolean dServerSent = false;

    private final RandomData rng;
    private final Cipher rsa;
    private final KeyPair rsaPair;
    private final RSAPrivateKey privateKey;
    private final RSAPublicKey publicKey;

    // TODO: d_server ARR_LEN - 1
    // MODULUS AND D SERVER CAN BE GET ONLY ONCE

    /**
     *
     * @param bArray
     * @param bOffset
     * @param bLength
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new RSAClient(bArray, bOffset, bLength);
    }

    /**
     *
     * @param buffer
     * @param offset
     * @param length
     */
    public RSAClient(byte[] buffer, short offset, byte length) {
        tmpBuffer = JCSystem.makeTransientByteArray(ARR_LEN, JCSystem.CLEAR_ON_RESET);

        rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        rsa = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);

        rsaPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_2048);
        privateKey = (RSAPrivateKey) rsaPair.getPrivate();
        publicKey = (RSAPublicKey) rsaPair.getPublic();

        register();
    }

    /**
     *
     * @param apdu
     */
    public void process(APDU apdu) {
        if (selectingApplet())
            return;

        byte[] apduBuffer = apdu.getBuffer();

        if (apduBuffer[ISO7816.OFFSET_CLA] != RSA_SMPC_CLIENT)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);

        switch (apduBuffer[ISO7816.OFFSET_INS]) {
            case GENERATE_KEYS:
                generateRSAKeys(apdu);
                break;

            case GET_KEYS:
                getRSAKeys(apdu);
                break;

            case SET_MESSAGE:
                setMessage(apdu);
                break;

            case SIGNATURE:
                signRSAMessage(apdu);
                break;

            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    // JCMathLib

    /**
     *
     * @param a
     * @param b
     */
    public void subtract(byte[] a, byte[] b) {
        short akku = 0;
        short subtraction_result;
        short i = (short) (a.length - 1);
        short j = (short) (b.length - 1);
        for (; i >= 0 && j >= 0; i--, j--) {
            akku = (short) (akku + (short) (b[j] & digitMask));
            subtraction_result = (short) ((a[i] & digitMask) - (akku & digitMask));

            a[i] = (byte) (subtraction_result & digitMask);
            akku = (short) ((akku >> digitLen) & digitMask);
            if (subtraction_result < 0) {
                akku++;
            }
        }

        // deal with carry as long as there are digits left in this
        while (i >= 0 && akku != 0) {
            subtraction_result = (short) ((a[i] & digitMask) - (akku & digitMask));
            a[i] = (byte) (subtraction_result & digitMask);
            akku = (short) ((akku >> digitLen) & digitMask);
            if (subtraction_result < 0) {
                akku++;
            }
            i--;
        }
    }

    /**
     *
     * @param apdu
     */
    private void generateRSAKeys(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();

        if (apduBuffer[ISO7816.OFFSET_P1] != 0x00 || apduBuffer[ISO7816.OFFSET_P2] != 0x00)
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

        publicKey.setExponent(E, (short) 0, (short) E.length);
        rsaPair.genKeyPair();

        privateKey.getExponent(tmpBuffer, (short) 0);

        // TODO: zitra ja taky den, dpc
        rng.generateData(DClient, (short) 0, (short) DClient.length);
        subtract(DServer, DClient);

        privateKey.setExponent(DClient, (short) 0, (short) DClient.length);

        nSent = false;
        dServerSent = false;
    }

    /**
     *
     * @param num
     * @param apdu
     */
    private void sendNum(byte[] num,  APDU apdu) {
        Util.arrayCopyNonAtomic(num, (short) 0, apdu.getBuffer(), (short) 0, ARR_LEN);
        apdu.setOutgoingAndSend((short) 0, ARR_LEN);
    }

    /**
     *
     * @param apdu
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

                sendNum(N, apdu);
                nSent = true;
                break;

            case GET_D_SERVER:
                if (dServerSent)
                    ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);

                sendNum(DServer, apdu);
                dServerSent = true;
                break;

            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    /**
     *
     * @param apdu
     */
    private void setMessage(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();

        if (apduBuffer[ISO7816.OFFSET_P1] != 0)
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

        short lc = (short) ((short) apduBuffer[ISO7816.OFFSET_LC] & digitMask);
        byte p2 = apduBuffer[ISO7816.OFFSET_P2];

        if (p2 > 0x01)
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

        short position = (short) (ARR_LEN - (p2 * 0xFF + lc));
        Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, MSG, position, lc);

        messageSet = true;
    }

    /**
     *
     * @param apdu
     */
    private void signRSAMessage(APDU apdu) {
        if (!privateKey.isInitialized() || !messageSet)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

        byte[] apduBuffer = apdu.getBuffer();

        if (apduBuffer[ISO7816.OFFSET_P1] != 0x00 || apduBuffer[ISO7816.OFFSET_P2] != 0x00)
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

        rsa.init(privateKey, Cipher.MODE_DECRYPT);
        rsa.doFinal(tmpBuffer, (short) 0, (short) tmpBuffer.length, apduBuffer, (short) 0);

        messageSet = false;
        apdu.setOutgoingAndSend((short) 0, ARR_LEN);
    }

}
