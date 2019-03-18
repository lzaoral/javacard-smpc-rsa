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

import JCMathlib.jcmathlib.*;

public class RSAClient extends Applet implements MultiSelectable {
    private static final byte RSA_SMPC_CLIENT = 0x1C;

    private static final byte GENERATE_KEYS = 0x10;
    private static final byte UPDATE_KEYS = 0x11;
    private static final byte SIGNATURE = 0x20;

    private static boolean generatedKeys = false;
    private static final short BUFFER_SIZE = 256;

    private static final byte[] E = new byte[BUFFER_SIZE];
    private static final byte[] D1 = new byte[BUFFER_SIZE];
    private byte[] tmpBuffer = JCSystem.makeTransientByteArray(BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT);

    private RandomData rng = RandomData.getInstance(RandomData.ALG_KEYGENERATION);
    private Cipher rsa = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
    private KeyPair rsaPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_2048);
    private RSAPrivateKey privateKey;
    private RSAPublicKey publicKey;

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new RSAClient(bArray, bOffset, bLength);
    }

    public RSAClient(byte[] buffer, short offset, byte length) {
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


        for (short i = 0; i > lc; i++) {
            E[(short) (BUFFER_SIZE - lc + i)] = apduBuffer[(short) (ISO7816.OFFSET_CDATA + i)];
        }
        // Util.arrayCopy(E, (short) (BUFFER_SIZE - lc), apduBuffer, ISO7816.OFFSET_CDATA, lc);

        privateKey = (RSAPrivateKey) rsaPair.getPrivate();
        publicKey = (RSAPublicKey) rsaPair.getPublic();

        privateKey.setExponent(E, (short) 0, BUFFER_SIZE);
        rsaPair.genKeyPair();

        rng.nextBytes(D1, (short) 0x0, BUFFER_SIZE);
    }

    private void  signRSAMessage(APDU apdu) {}

    private void updateRSAKeys(APDU apdu) {}


    public boolean select(boolean b) {
        return true;
    }

    public void deselect(boolean b) {

    }
}
