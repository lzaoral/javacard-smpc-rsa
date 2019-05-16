package smpc_rsa;

import javacard.framework.*;

import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;

import javacardx.crypto.Cipher;

import smpc_rsa.jcmathlib.Bignat;
import smpc_rsa.jcmathlib.Bignat_Helper;
import smpc_rsa.jcmathlib.ECConfig;

/**
 * The {@link RSAServer} class represents JavaCard applet used
 * for the purpose of server signing.
 *
 * It is recommended to use the provided proxy application
 * to send commands to the given card.
 *
 * @author Lukas Zaoral
 */
public class RSAServer extends Applet {

    private static final byte CLA_RSA_SMPC_SERVER = (byte) 0x80; // TODO:

    /**
     * Instruction codes
     */
    private static final byte INS_GENERATE_KEYS = 0x10;
    private static final byte INS_SET_CLIENT_KEYS = 0x12;
    private static final byte INS_GET_PUBLIC_MODULUS = 0x14;
    private static final byte INS_SET_CLIENT_SIGNATURE = 0x16;
    private static final byte INS_SIGNATURE = 0x18;
    private static final byte INS_GET_SIGNATURE = 0x20;
    private static final byte INS_RESET = 0x22;

    /**
     * P1 parameters of the INS_SET_CLIENT_KEYS instruction
     */
    private static final byte P1_SET_D1_SERVER = 0x00;
    private static final byte P1_SET_N1 = 0x01;

    /**
     * P1 parameters of the INS_SET_CLIENT_SIGNATURE instruction
     */
    private static final byte P1_SET_MESSAGE = 0x00;
    private static final byte P1_SET_SIGNATURE = 0x01;

    /**
     * Variables holding the state of sent keys and set messages
     */
    private final byte[] keyState = new byte[2];
    private final byte[] sigState; // will be constantly changed
    private byte publicModulusState = 0x00;

    /**
     * Helper arrays
     */
    private final byte[] E = new byte[]{0x01, 0x00, 0x01};
    private final byte[] publicModulus = new byte[Common.PARTIAL_MODULUS_BYTE_LENGTH * 2];

    /**
     * Bignats
     */
    private final BignatSgn tmpBignatSmall1;
    private final BignatSgn tmpBignatSmall2;
    private final BignatSgn tmpBignatBig;
    private final BignatSgn clientSignature;
    private final BignatSgn message;
    private final BignatSgn SGN;

    // for comprimality test
    private final BignatSgn newA;
    private final BignatSgn newB;

    private final BignatSgn n1;
    private final BignatSgn n2;
    private final BignatSgn s1;
    private final BignatSgn s2;

    private final BignatSgn oldA;
    private final BignatSgn oldB;
    private final BignatSgn quotient;
    private final BignatSgn tmpSmall;
    private final BignatSgn tmpBig;

    // for BignatSgn
    private final Bignat bignatSgnHelper;

    /**
     * RSA objects
     */
    private RSAPrivateKey clientPrivateKey;
    private RSAPublicKey clientPublicKey;

    private KeyPair serverRsaPair;
    private RSAPrivateKey serverPrivateKey;
    private RSAPublicKey serverPublicKey;

    private Cipher rsaClient, rsaClientVerify, rsaServer;

    /**
     * The {@link BignatSgn} class represents Bignat object with support
     * of negative numbers and subtraction, multiplication and division
     * extended to support this feature.
     */
    public class BignatSgn extends Bignat {

        public static final byte POSITIVE_OR_ZERO = 0x01;
        public static final byte NEGATIVE = 0x00;

        private byte sign = POSITIVE_OR_ZERO;

        public BignatSgn(short size, byte allocatorType, Bignat_Helper bignatHelper) {
            super(size, allocatorType, bignatHelper);
        }

        public void copy(BignatSgn other) {
            super.copy(other);
            sign = other.sign;
        }

        public void clone(BignatSgn other) {
            super.clone(other);
            sign = other.sign;
        }

        public void mult(BignatSgn x, BignatSgn y) {
            super.mult(x, y);
            sign = x.sign == y.sign || this.is_zero() ? POSITIVE_OR_ZERO : NEGATIVE;
        }

        public void remainder_divide(BignatSgn divisor, BignatSgn quotient) {
            super.remainder_divide(divisor, quotient);
            sign = divisor.sign == quotient.sign || this.is_zero() ? POSITIVE_OR_ZERO : NEGATIVE;
        }

        public void subtract(BignatSgn other) {
            bignatSgnHelper.copy(other);

            if (lesser(other)) {
                sign = sign == other.sign && other.sign == POSITIVE_OR_ZERO ? NEGATIVE : POSITIVE_OR_ZERO;
                bignatSgnHelper.subtract(this);
                copy(bignatSgnHelper);
                setZeroSign();
                return;
            }

            if (sign == other.sign)
                subtract(bignatSgnHelper);
            else
                add(bignatSgnHelper);

            setZeroSign();
        }

        private void setZeroSign() {
            if (is_zero())
                sign = POSITIVE_OR_ZERO;
        }

    }

    /**
     * Creates the instance of this applet. Used by the JavaCard runtime itself.
     *
     * Installation parameters
     * @param bArray bArray
     * @param bOffset bOffset
     * @param bLength bLength
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new RSAServer(bArray, bOffset, bLength);
    }

    /**
     * Constructor of {@link RSAServer} class. Allocates and creates all used objects.
     *
     * Installation parameters
     * @param bArray bArray
     * @param bOffset bOffset
     * @param bLength bLength
     * @throws ISOException with {@link CryptoException} reason
     */
    public RSAServer(byte[] bArray, short bOffset, byte bLength) {
        Bignat_Helper bignatHelper = new ECConfig().bnh;

        // bignatSgn
        bignatSgnHelper = new Bignat((short) (Common.PARTIAL_MODULUS_BYTE_LENGTH * 2), JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bignatHelper);

        // Allocate Bignats
        tmpBignatSmall1 = new BignatSgn(Common.PARTIAL_MODULUS_BYTE_LENGTH, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bignatHelper);
        tmpBignatSmall2 = new BignatSgn(Common.PARTIAL_MODULUS_BYTE_LENGTH, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bignatHelper);

        // for overflow
        tmpBignatBig = new BignatSgn((short) (Common.PARTIAL_MODULUS_BYTE_LENGTH * 2 + 1), JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bignatHelper);
        SGN = new BignatSgn((short) (Common.PARTIAL_MODULUS_BYTE_LENGTH * 2), JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bignatHelper);
        clientSignature = new BignatSgn(Common.PARTIAL_MODULUS_BYTE_LENGTH, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bignatHelper);
        message = new BignatSgn(Common.PARTIAL_MODULUS_BYTE_LENGTH, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bignatHelper);

        // ugly
        newA = new BignatSgn(Common.PARTIAL_MODULUS_BYTE_LENGTH, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bignatHelper);
        newB = new BignatSgn(Common.PARTIAL_MODULUS_BYTE_LENGTH, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bignatHelper);

        // ugly
        n1 = new BignatSgn(Common.PARTIAL_MODULUS_BYTE_LENGTH, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bignatHelper);
        n2 = new BignatSgn(Common.PARTIAL_MODULUS_BYTE_LENGTH, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bignatHelper);
        s1 = new BignatSgn(Common.PARTIAL_MODULUS_BYTE_LENGTH, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bignatHelper);
        s2 = new BignatSgn(Common.PARTIAL_MODULUS_BYTE_LENGTH, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bignatHelper);

        // ugly nazvy
        oldA = new BignatSgn(Common.PARTIAL_MODULUS_BYTE_LENGTH, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bignatHelper);
        oldB = new BignatSgn(Common.PARTIAL_MODULUS_BYTE_LENGTH, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bignatHelper);
        quotient = new BignatSgn(Common.PARTIAL_MODULUS_BYTE_LENGTH, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bignatHelper);
        tmpSmall = new BignatSgn(Common.PARTIAL_MODULUS_BYTE_LENGTH, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bignatHelper);
        tmpBig = new BignatSgn((short) (Common.PARTIAL_MODULUS_BYTE_LENGTH * 2), JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bignatHelper);

        sigState = JCSystem.makeTransientByteArray((short) 2, JCSystem.CLEAR_ON_RESET);

        try {
            // Allocate keys
            serverRsaPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_2048);
            serverPrivateKey = (RSAPrivateKey) serverRsaPair.getPrivate();
            serverPublicKey = (RSAPublicKey) serverRsaPair.getPublic();

            clientPrivateKey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_2048, false);
            clientPublicKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_2048, false);

            // Allocate RSA engines
            rsaClient = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
            rsaClientVerify = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
            rsaServer = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
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

        if (apduBuffer[ISO7816.OFFSET_CLA] != CLA_RSA_SMPC_SERVER)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);

        switch (apduBuffer[ISO7816.OFFSET_INS]) {
            case INS_GENERATE_KEYS:
                generateRSAKeys(apdu);
                break;

            case INS_SET_CLIENT_KEYS:
                setClientKeys(apdu);
                break;

            case INS_GET_PUBLIC_MODULUS:
                getPublicModulus(apdu);
                break;

            case INS_SET_CLIENT_SIGNATURE:
                setClientSignature(apdu);
                break;

            case INS_SIGNATURE:
                signRSAMessage(apdu);
                break;

            case INS_GET_SIGNATURE:
                getFinalSignature(apdu);
                break;

            case INS_RESET:
                reset(apdu);
                break;

            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    /**
     * Generates the server private exponent and the server partial modulus.
     * If the keys have already been generated, throws an exception. To regenerate them,
     * use the INS_RESET command first and then try again.
     *
     * @param apdu object representing the communication between the card and the world
     * @throws ISOException SW_COMMAND_NOT_ALLOWED if the keys have already been generated
     * @throws ISOException SW_INCORRECT_P1P2
     * @throws ISOException with {@link CryptoException} reason
     */
    private void generateRSAKeys(APDU apdu) {
        if (serverPrivateKey.isInitialized() || serverPublicKey.isInitialized())
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);

        Common.checkZeroP1P2(apdu.getBuffer());

        try {
            serverPublicKey.setExponent(E, (short) 0, (short) E.length);
            serverRsaPair.genKeyPair();
            clientPublicKey.setExponent(E, (short) 0, (short) E.length);

            rsaServer.init(serverPrivateKey, Cipher.MODE_DECRYPT);
        } catch (CryptoException e) {
            ISOException.throwIt(e.getReason());
        }
    }

    /**
     * TODO refactor
     * @param apdu
     */
    private void setClientKeys(APDU apdu) {
        if (!serverPrivateKey.isInitialized() || !serverPublicKey.isInitialized())
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

        byte[] apduBuffer = apdu.getBuffer();
        switch (apduBuffer[ISO7816.OFFSET_P1]) {
            case P1_SET_D1_SERVER:
                if (keyState[P1_SET_D1_SERVER] == Common.DATA_TRANSFERRED)
                    ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);

                Common.setNumber(apdu, tmpBignatSmall1.as_byte_array());
                updateKey(apdu);
                break;

            case P1_SET_N1:
                if (keyState[P1_SET_N1] == Common.DATA_TRANSFERRED)
                    ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);

                Common.setNumber(apdu, tmpBignatSmall2.as_byte_array());
                updateKey(apdu);
                break;

            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    /**
     *
     * @param apdu
     */
    private void updateKey(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        byte p1 = apduBuffer[ISO7816.OFFSET_P1];
        byte p2 = apduBuffer[ISO7816.OFFSET_P2];

        keyState[p1] = Common.updateLoadState(keyState[p1], p2);
        if (keyState[p1] != Common.DATA_TRANSFERRED)
            return;

        if (p1 == P1_SET_D1_SERVER) {
            clientPrivateKey.setExponent(tmpBignatSmall1.as_byte_array(), (short) 0, tmpBignatSmall1.length());
            tmpBignatSmall1.erase();
        } else {
            byte[] modulus = tmpBignatSmall2.as_byte_array();

            if ((modulus[0] & Common.HIGHEST_BIT_MASK) != Common.HIGHEST_BIT_MASK)
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

            clientPrivateKey.setModulus(modulus, (short) 0, (short) modulus.length);
            clientPublicKey.setModulus(modulus, (short) 0, (short) modulus.length);

            tmpBignatSmall2.erase();
        }

        if (clientPrivateKey.isInitialized())
            rsaClient.init(clientPrivateKey, Cipher.MODE_DECRYPT);

        if (clientPublicKey.isInitialized())
            rsaClientVerify.init(clientPublicKey, Cipher.MODE_ENCRYPT);
    }

    /**
     *
     * @param apdu
     */
    private void getPublicModulus(APDU apdu) {
        if (!clientPrivateKey.isInitialized() || !clientPublicKey.isInitialized())
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

        byte[] apduBuffer = apdu.getBuffer();
        byte p2 = apduBuffer[ISO7816.OFFSET_P2];
        if (apduBuffer[ISO7816.OFFSET_P1] != 0x00)
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

        if (p2 != Common.P2_PART_0 && p2 != Common.P2_PART_1)
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

        // tmpBignatBig is empty iff this method is invoked for the first time
        if (publicModulusState == 0x00) {
            clientPrivateKey.getModulus(tmpBignatSmall1.as_byte_array(), (short) 0);
            serverPrivateKey.getModulus(tmpBignatSmall2.as_byte_array(), (short) 0);

            if (!isCoprime(tmpBignatSmall1, tmpBignatSmall2))
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);

            tmpBignatBig.mult(tmpBignatSmall2, tmpBignatSmall1);

            // 4096-bit modulus check
            if (tmpBignatBig.as_byte_array()[0] != 0x00 ||
                    (tmpBignatBig.as_byte_array()[1] & Common.HIGHEST_BIT_MASK) != Common.HIGHEST_BIT_MASK)
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

            Util.arrayCopyNonAtomic(tmpBignatBig.as_byte_array(), (short) 1, publicModulus, (short) 0,
                    (short) (Common.PARTIAL_MODULUS_BYTE_LENGTH * 2));

            tmpBignatSmall1.erase();
            tmpBignatSmall2.erase();
            tmpBignatBig.erase();
        }

        // each part has to be sent at least once, thus publicModulusState will be equal the DATA_TRANSFERRED
        if (p2 == Common.P2_PART_0) {
            Common.sendNum(apdu, publicModulus, (short) 0, false);
            publicModulusState |= 0x20;
            return;
        }

        Common.sendNum(apdu, tmpBignatBig.as_byte_array(), Common.PARTIAL_MODULUS_BYTE_LENGTH, false);
        publicModulusState |= 0x02;
    }

    /**
     *
     * @param apdu
     */
    // reset used Bignums
    private void setClientSignature(APDU apdu) {
        if (publicModulusState != Common.DATA_TRANSFERRED)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

        if (sigState[P1_SET_MESSAGE] == Common.DATA_TRANSFERRED
                && sigState[P1_SET_SIGNATURE] == Common.DATA_TRANSFERRED) {

            Common.clearByteArray(sigState);
            message.erase();
            clientSignature.erase();
        }

        byte[] apduBuffer = apdu.getBuffer();
        byte p1 = apduBuffer[ISO7816.OFFSET_P1];
        switch (p1) {
            case P1_SET_MESSAGE:
                if (sigState[P1_SET_MESSAGE] == Common.DATA_TRANSFERRED)
                    ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);

                Common.setNumber(apdu, message.as_byte_array());
                break;

            case P1_SET_SIGNATURE:
                if (sigState[P1_SET_SIGNATURE] == Common.DATA_TRANSFERRED)
                    ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);

                Common.setNumber(apdu, clientSignature.as_byte_array());
                break;

            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        sigState[p1] = Common.updateLoadState(sigState[p1], apduBuffer[ISO7816.OFFSET_P2]);
    }

    /**
     *
     * @param apdu
     */
    private void signRSAMessage(APDU apdu) {
        if (sigState[P1_SET_MESSAGE] != Common.DATA_TRANSFERRED || sigState[P1_SET_SIGNATURE] != Common.DATA_TRANSFERRED)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

        Common.checkZeroP1P2(apdu.getBuffer());

        clientPrivateKey.getModulus(n1.as_byte_array(), (short) 0);
        serverPrivateKey.getModulus(n2.as_byte_array(), (short) 0);

        rsaClient.doFinal(message.as_byte_array(), (short) 0, message.length(), tmpBignatSmall1.as_byte_array(), (short) 0);
        s1.mod_mult(clientSignature, tmpBignatSmall1, n1);
        rsaClientVerify.doFinal(s1.as_byte_array(), (short) 0, s1.length(), tmpBignatSmall1.as_byte_array(), (short) 0);

        if (!tmpBignatSmall1.same_value(message)) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        rsaServer.doFinal(message.as_byte_array(), (short) 0, message.length(), s2.as_byte_array(), (short) 0);
        inverse(n1, n2, tmpSmall);

        s2.mod_sub(s1, n2);
        tmpSmall.mod_mult(s2, tmpSmall, n2);
        SGN.mult(tmpSmall, n1);
        SGN.add(s1);

        /*
        // Compute the full signature
        Bignum s = Bignum::mod_exp(m, d2, n2) - s1;
        s.mod_mul_self(Bignum::inverse(n1, n2), n2);
        s *= n1;
        s += s1;
        */

        // TODO: clean all?

        tmpBignatSmall1.erase();
        tmpBignatSmall2.erase();
        tmpBignatBig.erase();
        newA.erase();
        newB.erase();
        n1.erase();
        n2.erase();
        s1.erase();
        s2.erase();
        oldA.erase();
        oldB.erase();
        quotient.erase();
        tmpSmall.erase();
        tmpBig.erase();
    }


    /**
     *
     * @param apdu
     */
    private void getFinalSignature(APDU apdu) {
        if (SGN.is_zero())
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

        byte[] apduBuffer = apdu.getBuffer();
        if (apduBuffer[ISO7816.OFFSET_P1] != 0x00)
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

        switch (apduBuffer[ISO7816.OFFSET_P2]) {
            case Common.P2_PART_0:
                Common.sendNum(apdu, SGN.as_byte_array(), (short) 0, false);
                break;

            case Common.P2_PART_1:
                Common.sendNum(apdu, SGN.as_byte_array(), Common.PARTIAL_MODULUS_BYTE_LENGTH, false);
                break;

            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    /**
     * Zeroes out all arrays and resets the applet to the initial state.
     *
     * @param apdu object representing the communication between the card and the world
     * @throws ISOException SW_INCORRECT_P1P2
     */
    private void reset(APDU apdu) {
        Common.checkZeroP1P2(apdu.getBuffer());

        clientPrivateKey.clearKey();
        clientPublicKey.clearKey();

        serverPrivateKey.clearKey();
        serverPublicKey.clearKey();

        publicModulusState = 0x00;

        tmpBignatSmall1.erase();
        tmpBignatSmall2.erase();
        tmpBignatBig.erase();
        clientSignature.erase();
        message.erase();
        SGN.erase();
        newA.erase();
        newB.erase();
        n1.erase();
        n2.erase();
        s1.erase();
        s2.erase();
        oldA.erase();
        oldB.erase();
        quotient.erase();
        tmpSmall.erase();
        tmpBig.erase();

        Common.clearByteArray(keyState);
        Common.clearByteArray(sigState);
    }

    /**
     * TODO:
     * @param a
     * @param b
     * @return
     */
    public boolean isCoprime(BignatSgn a, BignatSgn b) {

        //nemazat?
        newA.erase();
        newB.erase();

        newA.copy(a);
        newB.copy(b);

        //TODO: nicer
        while (!newB.is_zero()) {
            tmpSmall.copy(newB);
            newA.mod(newB);
            newB.copy(newA);
            newA.copy(tmpSmall);
        }

        return newA.same_value(Bignat_Helper.ONE);

    }

    /**
     * TODO:
     * @param a
     * @param n
     * @param res
     */
    public void inverse(BignatSgn a, BignatSgn n, BignatSgn res) {

        oldA.erase();
        oldB.erase();
        newA.erase();
        newB.erase();
        quotient.erase();
        tmpSmall.erase();
        tmpBig.erase();

        oldA.copy(n);
        newB.one();
        newA.copy(a);

        if (oldA.lesser(newA))
            newA.subtract(oldA);

        while (!newA.is_zero()) {
            tmpBig.copy(oldA);
            tmpBig.remainder_divide(newA, quotient);

            tmpSmall.copy(newB);
            tmpBig.mult(quotient, newB);
            newB.copy(oldB);
            oldB.clone(tmpSmall);
            newB.subtract(tmpBig);

            tmpSmall.copy(newA);
            tmpBig.mult(quotient, newA);
            newA.copy(oldA);
            oldA.clone(tmpSmall);
            newA.subtract(tmpBig);
        }

        if (!oldA.lesser(Bignat_Helper.ONE) && !oldA.same_value(Bignat_Helper.ONE)
                && oldA.sign == BignatSgn.POSITIVE_OR_ZERO)
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);

        if (oldB.sign == BignatSgn.NEGATIVE) {
            tmpSmall.copy(n);
            tmpSmall.subtract(oldB);
            oldB.copy(tmpSmall);
        }

        res.copy(oldB);
    }

}
