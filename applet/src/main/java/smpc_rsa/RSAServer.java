package smpc_rsa;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

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
 * <p>
 * It is recommended to use the provided proxy application
 * to send commands to the given card.
 *
 * @author Lukas Zaoral
 */
public class RSAServer extends Applet {

    private static final byte CLA_RSA_SMPC_SERVER = (byte) 0x80;

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
    private final byte[] sigState; // transient, will be constantly changed
    private byte publicModulusState = 0x00;

    /**
     * Helper arrays
     */
    private final byte[] E = new byte[]{0x01, 0x00, 0x01};
    private final byte[] publicModulus = new byte[Common.PARTIAL_MODULUS_BYTE_LENGTH * 2];

    /**
     * Bignats
     */
    private final BignatSgn clientSignature;
    private final BignatSgn message;
    private final BignatSgn s;

    private final BignatSgn n1;
    private final BignatSgn n2;
    private final BignatSgn s1;

    // for coprimality test and modular inversion
    private final BignatSgn newA;
    private final BignatSgn newB;
    private final BignatSgn oldA;
    private final BignatSgn oldB;
    private final BignatSgn quotient;

    // helper bignats
    private final BignatSgn tmpSmall1;
    private final BignatSgn tmpSmall2;
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
     * The {@link BignatSgn} class represents {@link Bignat} object with support
     * of negative numbers and subtraction, multiplication and division
     * extended to support this feature.
     * <p>
     * The constructor and methods have the same meaning, see documentation
     * of {@link Bignat}.
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

        public void mult(BignatSgn x, BignatSgn y) {
            super.mult(x, y);
            sign = x.sign == y.sign || this.is_zero() ? POSITIVE_OR_ZERO : NEGATIVE;
        }

        public void remainder_divide(BignatSgn divisor, BignatSgn quotient) {
            super.remainder_divide(divisor, quotient);
            sign = divisor.sign == quotient.sign || this.is_zero() ? POSITIVE_OR_ZERO : NEGATIVE;
        }

        public void subtract(BignatSgn other) {
            bignatSgnHelper.resize_to_max(true);
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
     * <p>
     * Installation parameters
     *
     * @param bArray  bArray
     * @param bOffset bOffset
     * @param bLength bLength
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new RSAServer(bArray, bOffset, bLength);
    }

    /**
     * Constructor of {@link RSAServer} class. Allocates and creates all used objects.
     * <p>
     * Installation parameters
     *
     * @param bArray  bArray
     * @param bOffset bOffset
     * @param bLength bLength
     * @throws ISOException with {@link CryptoException} reason
     */
    public RSAServer(byte[] bArray, short bOffset, byte bLength) {
        Bignat_Helper bignatHelper = new ECConfig((short) 256).bnh;
        bignatHelper.FLAG_FAST_MULT_VIA_RSA = false; // the speed-up does not work with the emulator

        // bignatSgn
        bignatSgnHelper = new Bignat((short) (Common.PARTIAL_MODULUS_BYTE_LENGTH * 2), JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bignatHelper);

        // helper bignats
        tmpSmall1 = new BignatSgn(Common.PARTIAL_MODULUS_BYTE_LENGTH, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bignatHelper);
        tmpSmall2 = new BignatSgn(Common.PARTIAL_MODULUS_BYTE_LENGTH, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bignatHelper);
        // longer for possible overflow in modulus multiplication
        tmpBig = new BignatSgn((short) (Common.PARTIAL_MODULUS_BYTE_LENGTH * 2 + 1), JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bignatHelper);

        // signing
        message = new BignatSgn(Common.PARTIAL_MODULUS_BYTE_LENGTH, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bignatHelper);
        clientSignature = new BignatSgn(Common.PARTIAL_MODULUS_BYTE_LENGTH, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bignatHelper);
        s = new BignatSgn((short) (Common.PARTIAL_MODULUS_BYTE_LENGTH * 2), JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bignatHelper);
        s1 = new BignatSgn(Common.PARTIAL_MODULUS_BYTE_LENGTH, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bignatHelper);
        n1 = new BignatSgn(Common.PARTIAL_MODULUS_BYTE_LENGTH, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bignatHelper);
        n2 = new BignatSgn(Common.PARTIAL_MODULUS_BYTE_LENGTH, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bignatHelper);

        // coprimality test + inversion
        newB = new BignatSgn(Common.PARTIAL_MODULUS_BYTE_LENGTH, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bignatHelper);
        newA = new BignatSgn(Common.PARTIAL_MODULUS_BYTE_LENGTH, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bignatHelper);
        oldA = new BignatSgn(Common.PARTIAL_MODULUS_BYTE_LENGTH, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bignatHelper);
        oldB = new BignatSgn(Common.PARTIAL_MODULUS_BYTE_LENGTH, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bignatHelper);
        quotient = new BignatSgn(Common.PARTIAL_MODULUS_BYTE_LENGTH, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bignatHelper);

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
     * @param apdu object representing the communication between the card and the terminal
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
     * @param apdu object representing the communication between the card and the terminal
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
     * Sets the value of server private exponent share and clients partial
     * modulus by segments described by the header in the APDU Buffer.
     * Server keys must be already generated. The server private exponent
     * share must be set before the public modulus.
     * <p>
     * P1 - specifies the data to be set
     *    - 0x00 - private exponent
     *    - 0x01 - modulus
     * <p>
     * Keys can be reset only by calling the INS_RESET instruction
     * after the keys have been fully set.
     *
     * @param apdu object representing the communication between the card and the terminal
     * @throws ISOException SW_CONDITIONS_NOT_SATISFIED if the server have not been generated
     * @throws ISOException SW_COMMAND_NOT_ALLOWED if the server share of client keys is already set
     * @throws ISOException SW_INCORRECT_P1P2
     */
    private void setClientKeys(APDU apdu) {
        if (!serverPrivateKey.isInitialized() || !serverPublicKey.isInitialized())
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

        byte[] apduBuffer = apdu.getBuffer();
        switch (apduBuffer[ISO7816.OFFSET_P1]) {
            case P1_SET_D1_SERVER:
                if (keyState[P1_SET_D1_SERVER] == Common.DATA_TRANSFERRED)
                    ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);

                Common.setNumber(apdu, tmpSmall1.as_byte_array());
                updateKey(apdu);
                break;

            case P1_SET_N1:
                if (keyState[P1_SET_N1] == Common.DATA_TRANSFERRED)
                    ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);

                Common.setNumber(apdu, tmpSmall2.as_byte_array());
                updateKey(apdu);
                break;

            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    /**
     * Sets the server share of client keys and updates the information about their state.
     *
     * @param apdu object representing the communication between the card and the terminal
     * @throws ISOException SW_WRONG_LENGTH if the partial modulus n1 is shorter
     * @throws ISOException with {@link CryptoException} reason
     */
    private void updateKey(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        byte p1 = apduBuffer[ISO7816.OFFSET_P1];
        byte p2 = apduBuffer[ISO7816.OFFSET_P2];

        keyState[p1] = Common.updateLoadState(keyState[p1], p2);
        if (keyState[p1] != Common.DATA_TRANSFERRED)
            return;

        try {
            if (p1 == P1_SET_D1_SERVER) {
                clientPrivateKey.setExponent(tmpSmall1.as_byte_array(), (short) 0, tmpSmall1.length());
                tmpSmall1.erase();
            } else {
                byte[] modulus = tmpSmall2.as_byte_array();

                // 2048-bit partial modulus check
                if ((modulus[0] & Common.HIGHEST_BIT_MASK) != Common.HIGHEST_BIT_MASK)
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

                clientPrivateKey.setModulus(modulus, (short) 0, (short) modulus.length);
                clientPublicKey.setModulus(modulus, (short) 0, (short) modulus.length);

                tmpSmall2.erase();
            }

            if (clientPrivateKey.isInitialized())
                rsaClient.init(clientPrivateKey, Cipher.MODE_DECRYPT);

            if (clientPublicKey.isInitialized())
                rsaClientVerify.init(clientPublicKey, Cipher.MODE_ENCRYPT);
        } catch (CryptoException e) {
            ISOException.throwIt(e.getReason());
        }
    }

    /**
     * Sends the public modulus depending on the P1 argument. The public modulus has to be of
     * correct length. The server keys must be generated and the server share of client keys
     * must be set first. After first run, the public modulus is available in the {@code publicModulus}
     * byte array. The public modulus must be retrieved at least once before signing.
     * After that, it can be retrieved an unlimited number of times.
     *
     * @param apdu object representing the communication between the card and the terminal
     * @throws ISOException SW_CONDITIONS_NOT_SATISFIED the keys are not set or generated
     * @throws ISOException SW_DATA_INVALID the partial moduli are not coprime
     * @throws ISOException SW_WRONG_LENGTH if the public modulus is not {@code PARTIAL_MODULUS_BYTE_LENGTH * 8 * 2}
     *                      bits long
     * @throws ISOException SW_INCORRECT_P1P2
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

        // tmpBig is empty iff this method is invoked for the first time
        if (publicModulusState == 0x00) {
            clientPrivateKey.getModulus(tmpSmall1.as_byte_array(), (short) 0);
            serverPrivateKey.getModulus(tmpSmall2.as_byte_array(), (short) 0);

            if (!isCoprime(tmpSmall1, tmpSmall2))
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);

            tmpBig.mult(tmpSmall1, tmpSmall2);
            byte[] tmpBigArray = tmpBig.as_byte_array();

            // 4096-bit public modulus check
            if (tmpBigArray[0] != 0x00 ||
                    (tmpBigArray[1] & Common.HIGHEST_BIT_MASK) != Common.HIGHEST_BIT_MASK)
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

            Util.arrayCopyNonAtomic(tmpBigArray, (short) 1, publicModulus, (short) 0,
                    (short) (Common.PARTIAL_MODULUS_BYTE_LENGTH * 2));

            tmpSmall1.erase();
            tmpSmall2.erase();
            tmpBig.erase();
        }

        // each part has to be sent at least once, thus publicModulusState will be equal the DATA_TRANSFERRED
        if (p2 == Common.P2_PART_0) {
            Common.sendNum(apdu, publicModulus, (short) 0, false);
            publicModulusState |= 0x20;
            return;
        }

        Common.sendNum(apdu, publicModulus, Common.PARTIAL_MODULUS_BYTE_LENGTH, false);
        publicModulusState |= 0x02;
    }

    /**
     * Sets the value of message and client signature share by segments
     * described by the header in the APDU Buffer. Server keys must be already generated.
     * Server share of client key must be already set and the public modulus must be at least once
     * retrieved.
     * <p>
     * P1 - specifies the data to be set
     *    - 0x00 - message
     *    - 0x01 - client signature share
     * <p>
     * If the data are fully set, any subsequent calls start the loading from scratch.
     *
     * @param apdu object representing the communication between the card and the world
     * @throws ISOException SW_CONDITIONS_NOT_SATISFIED if the server have not been generated
     * @throws ISOException SW_COMMAND_NOT_ALLOWED if the message or signature are already set
     * @throws ISOException SW_INCORRECT_P1P2
     */
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
     * Computes the final signature using RSA and saves it to the {@code s} Bignat.
     * Fails if the client signature share is fraudulent od corrupt.
     * All keys, message and client signature share must be fully set prior to signing.
     *
     * @param apdu object representing the communication between the card and the terminal
     * @throws ISOException SW_CONDITIONS_NOT_SATISFIED if the keys, message or client signature share
     *                      have not yet been fully set
     * @throws ISOException SW_WRONG_DATA if the client signature share is fraudulent od corrupt
     * @throws ISOException SW_INCORRECT_P1P2
     * @throws ISOException with {@link CryptoException} reason
     */
    private void signRSAMessage(APDU apdu) {
        if (sigState[P1_SET_MESSAGE] != Common.DATA_TRANSFERRED || sigState[P1_SET_SIGNATURE] != Common.DATA_TRANSFERRED)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

        Common.checkZeroP1P2(apdu.getBuffer());

        clientPrivateKey.getModulus(n1.as_byte_array(), (short) 0);
        serverPrivateKey.getModulus(n2.as_byte_array(), (short) 0);

        try {
            rsaClient.doFinal(message.as_byte_array(), (short) 0, message.length(), tmpSmall1.as_byte_array(), (short) 0);
            s1.mod_mult(clientSignature, tmpSmall1, n1);

            tmpSmall1.erase();
            rsaClientVerify.doFinal(s1.as_byte_array(), (short) 0, s1.length(), tmpSmall1.as_byte_array(), (short) 0);

            if (!tmpSmall1.same_value(message)) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }

            rsaServer.doFinal(message.as_byte_array(), (short) 0, message.length(), tmpSmall2.as_byte_array(), (short) 0);
        } catch (CryptoException e) {
            ISOException.throwIt(e.getReason());
        }

        tmpSmall2.mod_sub(s1, n2);
        inverse(n1, n2, tmpSmall1);
        tmpSmall1.mod_mult(tmpSmall1, tmpSmall2, n2);
        s.mult(tmpSmall1, n1);
        s.add(s1);

        n1.resize_to_max(true);
        n2.resize_to_max(true);
        s1.resize_to_max(true);
        tmpSmall1.resize_to_max(true);
        tmpSmall2.resize_to_max(true);
        tmpBig.resize_to_max(true);
    }


    /**
     * Sends the final signature depending on the P1 argument.
     * The keys signature must be computed first and can be retrieved any number of times.
     *
     * @param apdu object representing the communication between the card and the terminal
     * @throws ISOException SW_CONDITIONS_NOT_SATISFIED the final signature is has not been computed yet
     * @throws ISOException SW_INCORRECT_P1P2
     */
    private void getFinalSignature(APDU apdu) {
        if (s.is_zero())
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

        byte[] apduBuffer = apdu.getBuffer();
        if (apduBuffer[ISO7816.OFFSET_P1] != 0x00)
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

        switch (apduBuffer[ISO7816.OFFSET_P2]) {
            case Common.P2_PART_0:
                Common.sendNum(apdu, s.as_byte_array(), (short) 0, false);
                break;

            case Common.P2_PART_1:
                Common.sendNum(apdu, s.as_byte_array(), Common.PARTIAL_MODULUS_BYTE_LENGTH, false);
                break;

            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    /**
     * Zeroes out all arrays and resets the applet to the initial state.
     *
     * @param apdu object representing the communication between the card and the terminal
     * @throws ISOException SW_INCORRECT_P1P2
     */
    private void reset(APDU apdu) {
        Common.checkZeroP1P2(apdu.getBuffer());

        clientPrivateKey.clearKey();
        clientPublicKey.clearKey();

        serverPrivateKey.clearKey();
        serverPublicKey.clearKey();

        publicModulusState = 0x00;

        tmpSmall1.resize_to_max(true);
        tmpSmall2.resize_to_max(true);
        tmpBig.resize_to_max(true);
        message.resize_to_max(true);
        clientSignature.resize_to_max(true);
        s.resize_to_max(true);
        s1.resize_to_max(true);
        n1.resize_to_max(true);
        n2.resize_to_max(true);
        newA.resize_to_max(true);
        newB.resize_to_max(true);
        oldA.resize_to_max(true);
        oldB.resize_to_max(true);
        quotient.resize_to_max(true);

        Common.clearByteArray(keyState);
        Common.clearByteArray(sigState);
        Common.clearByteArray(publicModulus);
    }

    /**
     * Decides whether the numbers {@code a} and {@code b} are coprime.
     * Based on pseudo-code from Wikipedia: https://en.wikipedia.org/wiki/Euclidean_algorithm
     *
     * @param a number a
     * @param b number b
     * @return true if {@code a} and {@code b} are coprime, false otherwise.
     */
    public boolean isCoprime(BignatSgn a, BignatSgn b) {
        newA.copy(a);
        newB.copy(b);

        while (!newB.is_zero()) {
            oldB.copy(newB);
            newA.mod(newB);
            newB.copy(newA);
            newA.copy(oldB);
        }

        return newA.same_value(Bignat_Helper.ONE);
    }

    /**
     * Computes modular inverse of {@code a} modulo {@code n} and saves
     * the result into {@code res}.
     * Based on pseudo-code from Wikipedia: https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
     *
     * @param a number to inverted
     * @param n modulus
     * @param res result
     * @throws ISOException SW_DATA_INVALID if {@code a} is not invertible
     */
    public void inverse(BignatSgn a, BignatSgn n, BignatSgn res) {
        oldA.copy(n);
        oldB.erase();
        newB.one();
        newA.copy(a);

        if (oldA.lesser(newA))
            newA.subtract(oldA);

        while (!newA.is_zero()) {
            tmpBig.copy(oldA);
            tmpBig.remainder_divide(newA, quotient);

            tmpSmall1.copy(newB);
            tmpBig.mult(quotient, newB);
            newB.copy(oldB);
            oldB.copy(tmpSmall1);
            newB.subtract(tmpBig);

            tmpSmall1.copy(newA);
            tmpBig.mult(quotient, newA);
            newA.copy(oldA);
            oldA.copy(tmpSmall1);
            newA.subtract(tmpBig);
        }

        if (!oldA.lesser(Bignat_Helper.ONE) && !oldA.same_value(Bignat_Helper.ONE)
                && oldA.sign == BignatSgn.POSITIVE_OR_ZERO)
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);

        if (oldB.sign == BignatSgn.NEGATIVE) {
            tmpSmall1.copy(n);
            tmpSmall1.subtract(oldB);
            oldB.copy(tmpSmall1);
        }

        res.copy(oldB);
    }

}
