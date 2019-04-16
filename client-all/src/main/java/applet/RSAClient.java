package applet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.MultiSelectable;
import javacard.framework.Util;

import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.RandomData;

import javacardx.crypto.Cipher;

public class RSAClient extends Applet implements MultiSelectable {
    private static final byte RSA_SMPC_CLIENT = 0x1C;

    private static final byte GENERATE_KEYS = 0x10;
    private static final byte SET_MESSAGE = 0x11;

    private static final byte GET_KEYS = 0x15;
    private static final byte GET_N = 0x00;
    private static final byte GET_D_SERVER = 0x01;

    private static final byte SIGNATURE = 0x20;

    private static final byte TEST = 0x30;

    private static boolean generatedKeys = false;
    private static final short ARR_LEN = 256;

    // from JCMathLib
    public static final short digit_mask = 0xff;
    public static final short digit_len = 8;

    // E = 65537
    private final static byte[] E = new byte[]{0x01, 0x00, 0x01};

    private final byte[] N;
    private final byte[] DClient;
    private final byte[] DServer;

    private final byte[] MSG;
    private final byte[] SGN;

    private static boolean messageSet = false;

    private static boolean nSent = false;
    private static boolean dServerSent = false;

    private final RandomData rng;
    private final Cipher rsa;
    private final KeyPair rsaPair;
    private final RSAPrivateKey privateKey;
    private final RSAPublicKey publicKey;

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new RSAClient(bArray, bOffset, bLength);
    }

    public RSAClient(byte[] buffer, short offset, byte length) {
        N = new byte[ARR_LEN];
        DClient = new byte[ARR_LEN - 1];
        DServer = JCSystem.makeTransientByteArray(ARR_LEN, JCSystem.CLEAR_ON_RESET);

        MSG = JCSystem.makeTransientByteArray(ARR_LEN, JCSystem.CLEAR_ON_RESET);
        SGN = JCSystem.makeTransientByteArray(ARR_LEN, JCSystem.CLEAR_ON_RESET);

        rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        rsa = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);

        rsaPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_2048);
        privateKey = (RSAPrivateKey) rsaPair.getPrivate();
        publicKey = (RSAPublicKey) rsaPair.getPublic();

        register();
    }

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
                ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
    }

    // JCMathLib
    public void subtract(byte[] a, byte[] b) {
        short akku = 0;
        short subtraction_result;
        short i = (short) (a.length - 1);
        short j = (short) (b.length - 1);
        for (; i >= 0 && j >= 0; i--, j--) {
            akku = (short) (akku + (short) (b[j] & digit_mask));
            subtraction_result = (short) ((a[i] & digit_mask) - (akku & digit_mask));

            a[i] = (byte) (subtraction_result & digit_mask);
            akku = (short) ((akku >> digit_len) & digit_mask);
            if (subtraction_result < 0) {
                akku++;
            }
        }

        // deal with carry as long as there are digits left in this
        while (i >= 0 && akku != 0) {
            subtraction_result = (short) ((a[i] & digit_mask) - (akku & digit_mask));
            a[i] = (byte) (subtraction_result & digit_mask);
            akku = (short) ((akku >> digit_len) & digit_mask);
            if (subtraction_result < 0) {
                akku++;
            }
            i--;
        }
    }

    private void generateRSAKeys(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();

        if (apduBuffer[ISO7816.OFFSET_P1] != 0x00 || apduBuffer[ISO7816.OFFSET_P2] != 0x00)
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

        publicKey.setExponent(E, (short) 0, (short) E.length);
        rsaPair.genKeyPair();

        privateKey.getModulus(N, (short) 0);
        privateKey.getExponent(DServer, (short) 0);

        rng.generateData(DClient, (short) 0, (short) DClient.length);
        subtract(DServer, DClient);

        privateKey.setExponent(DClient, (short) 0, (short) DClient.length);

        generatedKeys = true;
        nSent = false;
        dServerSent = false;
    }

    private void sendNum(byte[] num,  APDU apdu) {
        Util.arrayCopyNonAtomic(num, (short) 0, apdu.getBuffer(), (short) 0, ARR_LEN);
        apdu.setOutgoingAndSend((short) 0, ARR_LEN);
    }

    private void getRSAKeys(APDU apdu) {
        if (!generatedKeys)
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

    private void setMessage(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();

        if (apduBuffer[ISO7816.OFFSET_P1] != 0)
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

        short lc = (short) ((short) apduBuffer[ISO7816.OFFSET_LC] & digit_mask);
        byte p2 = apduBuffer[ISO7816.OFFSET_P2];

        if (p2 > 0x01)
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

        short position = (short) (ARR_LEN - (p2 * 0xFF + lc));
        Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, MSG, position, lc);

        messageSet = true;
    }

    private void signRSAMessage(APDU apdu) {
        if (!generatedKeys || !messageSet)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

        byte[] apduBuffer = apdu.getBuffer();

        if (apduBuffer[ISO7816.OFFSET_P1] != 0x00 || apduBuffer[ISO7816.OFFSET_P2] != 0x00)
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

        rsa.init(privateKey, Cipher.MODE_DECRYPT);
        rsa.doFinal(MSG, (short) 0, (short) MSG.length, SGN, (short) 0);

        Util.arrayCopyNonAtomic(SGN, (short) 0, apduBuffer, (short) 0, ARR_LEN);
        apdu.setOutgoingAndSend((short) 0, ARR_LEN);
    }

    public boolean select(boolean b) {
        return true;
    }

    public void deselect(boolean b) {

    }
}
