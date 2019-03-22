package applet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.MultiSelectable;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;

import applet.jcmathlib.*;

public class RSAClient extends Applet implements MultiSelectable {
    private static final byte RSA_SMPC_CLIENT = 0x1C;

    private static final byte GENERATE_KEYS = 0x10;
    private static final byte UPDATE_KEYS = 0x11;
    private static final byte SIGNATURE = 0x20;

    private static boolean generatedKeys = false;
    private static final short BUFFER_SIZE = 256;

    private final Bignat E;
    private final Bignat N;
    private final Bignat D;
    private final Bignat D1;
    private final Bignat D2;
    private byte[] tmpBuffer;

    private final ECConfig jcMathCfg;
    private final Bignat_Helper bignatHelper;

    private final RandomData rng;
    private final Cipher rsa;
    private final KeyPair rsaPair;
    private RSAPrivateKey privateKey;
    private RSAPublicKey publicKey;

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new RSAClient(bArray, bOffset, bLength);
    }

    public RSAClient(byte[] buffer, short offset, byte length) {
        jcMathCfg = new ECConfig((short) 256);
        bignatHelper = jcMathCfg.bnh;

        E = new Bignat(new byte[256], bignatHelper);
        N = new Bignat(new byte[256], bignatHelper);
        D = new Bignat(new byte[256], bignatHelper);
        D1 = new Bignat(new byte[256], bignatHelper);
        D2 = new Bignat(new byte[256], bignatHelper);

        tmpBuffer = JCSystem.makeTransientByteArray(BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT);

        rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        rsa = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
        rsaPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_2048);

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

            case UPDATE_KEYS:
                updateRSAKeys(apdu);
                break;

            case SIGNATURE:
                signRSAMessage(apdu);
                break;

            default:
                ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
    }

    private void generateRSAKeys(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();

        short lc = (short) apduBuffer[ISO7816.OFFSET_LC];
        E.from_byte_array(lc, (short) 0, apduBuffer, ISO7816.OFFSET_CDATA);
        // Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, tmpBuffer, (short) (BUFFER_SIZE - lc), lc);

        privateKey = (RSAPrivateKey) rsaPair.getPrivate();
        publicKey = (RSAPublicKey) rsaPair.getPublic();

        publicKey.setExponent(E.as_byte_array(), (short) 0, E.length());
        rsaPair.genKeyPair();

        privateKey.getModulus(N.as_byte_array(), (short) 0);
        privateKey.getExponent(D.as_byte_array(), (short) 0);

        rng.nextBytes(tmpBuffer, (short) 0x0, BUFFER_SIZE);
        D1.from_byte_array(BUFFER_SIZE, (short) 0, apduBuffer, ISO7816.OFFSET_CDATA);

        D1.mod_add();
    }

    private void signRSAMessage(APDU apdu) {}

    private void updateRSAKeys(APDU apdu) {}

    public boolean select(boolean b) {
        return true;
    }

    public void deselect(boolean b) {

    }
}
