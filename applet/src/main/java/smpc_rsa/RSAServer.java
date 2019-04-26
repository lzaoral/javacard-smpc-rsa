package smpc_rsa;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.MultiSelectable;
import javacard.framework.Util;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateCrtKey;
import javacard.security.RSAPublicKey;
import javacard.security.RandomData;

import smpc_rsa.jcmathlib.Bignat;
import smpc_rsa.jcmathlib.Bignat_Helper;
import smpc_rsa.jcmathlib.ECConfig;

public class RSAServer extends Applet implements MultiSelectable {
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
        new RSAServer(bArray, bOffset, bLength);
    }

    public RSAServer(byte[] buffer, short offset, byte length) {
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
        D.mod_inv(P);

        Bignat foo = new Bignat(new byte[BUFFER_SIZE], bignatHelper);
        foo.mod_mult(E, D, P);

        if (!foo.equals(Bignat_Helper.ONE))
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);

        Bignat test = new Bignat(new byte[]{0x0,0x0,0x5}, bignatHelper);
        Bignat test1 = new Bignat(new byte[]{0x0,0x0,0x2}, bignatHelper);
        test1.mod_inv(test);

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

// P:  C92302CAB7ED54788B472D81DF50040B7984A4AA0F663DEF4DF2FF6FCAB31A1BAF3600D13D8F8686E67FFBC384D38D55333A4B61768A917BF6DEC23BD58E6A35AD8C30D67DB39D37973855968C3A8D640D9A0E03933238B5E63AB87FE007332EBFF3D7868A2F7D59BCCD8F4FE9F4436491F820AE565DD23E955ADA4EBEBDD6D7
// Q:  C33EB97C588EF94196041AE7C6FB39137087A2D1EED104E20A6099BFA11F808F34529F341C8627D62B8F5E88633845382DCFE6CB96A3E1F32352932FEF316E878E348C3240C1FC5BFF1AF9FFA6D447E926E7E1B91D5C4068DCE8B395CB33966BEA1B6A47AABE25867AC867D5BECBAD955D66F5CBF83B6DCE08774BC2CD539EEF

// N:  9966F35716C08A25B16D34502A3ADA14CF0870365EF6F52D7ADAEA2D0D179315A583012AEB05E281D4B984F5D3B9FF960BB8340BAA828AF82FEDC53D38A8A7D2B79CC4FE199DAB8036DF792A2B7DB18BA6E9B3BF6313B7FA83B4834111B47CFECDBCB00F4F579B56C3E979E35DB388DE63E9617977614595345B525BBD23A8BEAA759BE8453E0F085BEDD38215C2E2C29FB70F3C000832683BA5ADE499D2DDE27B71B64D454E466657CBDE15E5582CA30A3AE139AF5BD6E314CE9DF488E4ACD74A2560D1C783B768FA5139EC731098E9B5F6DF3EAB48098BF475B9799B50DB64891F5F2144E9D1F87EC7D7893F68F76358C15B06AB669C67189311C2108944B9
// pN: 9966F35716C08A25B16D34502A3ADA14CF0870365EF6F52D7ADAEA2D0D179315A583012AEB05E281D4B984F5D3B9FF960BB8340BAA828AF82FEDC53D38A8A7D2B79CC4FE199DAB8036DF792A2B7DB18BA6E9B3BF6313B7FA83B4834111B47CFECDBCB00F4F579B56C3E979E35DB388DE63E9617977614595345B525BBD23A8BD1E13DFA134C1C14E3AA28B186F77A5A3B5AAC7C001D0EF96E35214B52E00433797E91647EB38980945BC83C9FD4C5A15A930AF0CA22D6373FA9D4888C424D41A0E64A3C9090E1DD563FDEA564001C39C8174EF81FAB9906D31524D63F01611C9DF101D530FFC2F184731E06396A906696962448C5CCD5C5A7AC0EBB08477CEF4

// E: 010001
// D: 57FE9BE9120BE99638C3D1119AC25F73B8A50C58F88096E321A54EB38802D822557EED51C81332B251563988BD7AC563EFDF1ED0E865FA33AEBC961E9A945910C2A7E68288C9E3178C81A071F8F79F492AC4B51D422AC99C5F34783EC9A0CB72AE1D6207CA2303A9E9F59C51007F2D96FB8DFBCB9F7815B1BB1871883B7399801ACD2F1B0B764A46D6C07B93E607A6A023A21473ADEFE9B5FAFAB7240826692C27037F9A87A0BE606C3CC06BC735E248AC2CE11F38AA4455FC914ECF97FEFF386FC3B76AE656874C0ECA9E9F985CD47B0A92D7C65E8AF61572B3117ED10496EE3D64E9A8AFC9EBBD67884049737AF3240357EFF2EDF200407EC8F9CC053DC4C5
//    57FE9BE9120BE99638C3D1119AC25F73B8A50C58F88096E321A54EB38802D822557EED51C81332B251563988BD7AC563EFDF1ED0E865FA33AEBC961E9A945910C2A7E68288C9E3178C81A071F8F79F492AC4B51D422AC99C5F34783EC9A0CB72AE1D6207CA2303A9E9F59C51007F2D96FB8DFBCB9F7815B1BB1871883B7399801ACD2F1B0B764A46D6C07B93E607A6A023A21473ADEFE9B5FAFAB7240826692C27037F9A87A0BE606C3CC06BC735E248AC2CE11F38AA4455FC914ECF97FEFF386FC3B76AE656874C0ECA9E9F985CD47B0A92D7C65E8AF61572B3117ED10496EE3D64E9A8AFC9EBBD67884049737AF3240357EFF2EDF200407EC8F9CC053DC4C5