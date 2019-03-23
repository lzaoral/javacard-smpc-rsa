package applet;

import javacard.framework.*;

import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateCrtKey;
import javacard.security.RSAPublicKey;
import javacard.security.RandomData;

import applet.jcmathlib.*;

public class RSAClient extends Applet implements MultiSelectable {
    private static final byte RSA_SMPC_CLIENT = 0x1C;

    private static final byte GENERATE_KEYS = 0x10;
    private static final byte GET_N = 0x11;
    private static final byte GET_D2 = 0x12;
    private static final byte UPDATE_KEYS = 0x13;
    private static final byte SIGNATURE = 0x20;
    private static final byte TEST = 0x30;

    private static boolean generatedKeys = false;
    private static final short BUFFER_SIZE = 256;

    private final Bignat E;

    private final Bignat P;
    private final Bignat Q;

    private final Bignat N;
    private final Bignat phiN;

    private final Bignat D;
    private final Bignat D1;
    private final Bignat D2;
    private byte[] tmpBuffer;

    private final ECConfig jcMathCfg;
    private final Bignat_Helper bignatHelper;

    private final RandomData rng;
    private final KeyPair rsaPair;
    private RSAPrivateCrtKey privateKey;
    private RSAPublicKey publicKey;

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new RSAClient(bArray, bOffset, bLength);
    }

    public RSAClient(byte[] buffer, short offset, byte length) {
        jcMathCfg = new ECConfig(BUFFER_SIZE);
        bignatHelper = jcMathCfg.bnh;

        E = new Bignat(new byte[BUFFER_SIZE], bignatHelper);

        P = new Bignat((short) (BUFFER_SIZE / 2), JCSystem.CLEAR_ON_DESELECT, bignatHelper);
        Q = new Bignat((short) (BUFFER_SIZE / 2), JCSystem.CLEAR_ON_DESELECT, bignatHelper);

        N = new Bignat(new byte[BUFFER_SIZE], bignatHelper);
        phiN = new Bignat(BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT, bignatHelper);

        D = new Bignat(BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT, bignatHelper);
        D1 = new Bignat(new byte[BUFFER_SIZE], bignatHelper);
        D2 = new Bignat(BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT, bignatHelper);

        tmpBuffer = JCSystem.makeTransientByteArray(BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT);

        rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        rsaPair = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_2048);

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

            case GET_N:
                if (!generatedKeys)
                    ISOException.throwIt(ISO7816.SW_LAST_COMMAND_EXPECTED);

                Util.arrayCopyNonAtomic(N.as_byte_array(), (short) 0, apduBuffer, (short) 0, BUFFER_SIZE);
                apdu.setOutgoingAndSend((short) 0, BUFFER_SIZE);
                break;

            case GET_D2:
                if (!generatedKeys)
                    ISOException.throwIt(ISO7816.SW_LAST_COMMAND_EXPECTED);

                Util.arrayCopyNonAtomic(D2.as_byte_array(), (short) 0, apduBuffer, (short) 0, BUFFER_SIZE);
                apdu.setOutgoingAndSend((short) 0, BUFFER_SIZE);
                break;

            case UPDATE_KEYS:
                updateRSAKeys(apdu);
                break;

            case SIGNATURE:
                signRSAMessage(apdu);
                break;

            case TEST:
                test(apdu);
                break;

            default:
                ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
    }

    private void generateRSAKeys(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();

        short lc = (short) apduBuffer[ISO7816.OFFSET_LC];
        E.from_byte_array(lc, (short) (BUFFER_SIZE - lc), apduBuffer, ISO7816.OFFSET_CDATA);

        privateKey = (RSAPrivateCrtKey) rsaPair.getPrivate();
        publicKey = (RSAPublicKey) rsaPair.getPublic();
        rsaPair.genKeyPair();

        privateKey.getP(P.as_byte_array(), (short) 0);
        privateKey.getQ(Q.as_byte_array(), (short) 0);
        N.mult(P, Q);

        P.subtract(Bignat_Helper.ONE);
        Q.subtract(Bignat_Helper.ONE);
        phiN.mult(P, Q);

        D.clone(E);
        D.mod_inv(phiN);

        rng.generateData(tmpBuffer, (short) 0x0, BUFFER_SIZE);
        D1.from_byte_array(BUFFER_SIZE, (short) 0, tmpBuffer, (short) 0);

        D2.clone(D1);
        D2.mod_sub(D, phiN);

        generatedKeys = true;
    }

    private void updateRSAKeys(APDU apdu) {
    }

    private void signRSAMessage(APDU apdu) {
    }

    private void test(APDU apdu) {
        generateRSAKeys(apdu);

        // Random data
        final byte[] message = {'T', 'h', 'i', 's', ' ', 'i', 's', ' ', 'a', ' ', 't', 'e', 's', 't', '!'};
        Bignat plaintext = new Bignat(BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT, bignatHelper);
        Bignat ciphertext = new Bignat(BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT, bignatHelper);
        plaintext.from_byte_array(message);
        ciphertext.clone(plaintext);

        ciphertext.mod_exp(E, N);
        ciphertext.mod_exp(D, N);

        if (Util.arrayCompare(ciphertext.as_byte_array(), (short) 0, plaintext.as_byte_array(), (short) 0,
                plaintext.length()) != 0)
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }

    public boolean select(boolean b) {
        return true;
    }

    public void deselect(boolean b) {

    }
}