package smpc_rsa;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;

import javacard.security.*;

import javacardx.crypto.Cipher;
import smpc_rsa.jcmathlib.Bignat;
import smpc_rsa.jcmathlib.Bignat_Helper;
import smpc_rsa.jcmathlib.ECConfig;

// TODO: Common constants to separate Class

public class RSAServer extends Applet {
    private static final byte CLA_RSA_SMPC_SERVER = 0x03;

    private static final byte INS_GENERATE_KEYS = 0x10;
    private static final byte INS_SET_CLIENT_KEYS = 0x12;
    private static final byte INS_GET_PUBLIC_N = 0x14;
    private static final byte INS_RESET = 0x16;
    private static final byte INS_SET_CLIENT_SIGNATURE = 0x18;
    private static final byte INS_SIGNATURE = 0x20;
    private static final byte INS_GET_SIGNATURE = 0x22;

    private static final byte P1_SET_N1 = 0x00;
    private static final byte P1_SET_D1_SERVER = 0x01;

    private static final byte P1_SET_MESSAGE = 0x00;
    private static final byte P1_SET_SIGNATURE = 0x01;

    //TODO: reset

    private static boolean generatedKeys = false;
    private static final short ARR_SIZE = 256;

    private final byte[] E = new byte[]{0x01, 0x00, 0x01};

    private final Bignat tmpBignatSmall1, tmpBignatSmall2, tmpBignatBig, clientSignature;

    private final Bignat SGN;
    private byte[] tmpBuffer;

    private final ECConfig jcMathCfg;
    private final Bignat_Helper bignatHelper;

    private final RSAPrivateKey clientPrivateKey;
    private final RSAPublicKey clientPublicKey;

    private final KeyPair serverRsaPair;
    private final RSAPrivateKey serverPrivateKey;
    private final RSAPublicKey serverPublicKey;

    private final Cipher rsaClient, rsaClientVerify, rsaServer;

    private final byte[] keyState = new byte[2];
    private final byte[] sigState = new byte[2];

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new RSAServer(bArray, bOffset, bLength);
    }

    public RSAServer(byte[] buffer, short offset, byte length) {
        jcMathCfg = new ECConfig(ARR_SIZE);
        bignatHelper = jcMathCfg.bnh;

        tmpBignatSmall1 = new Bignat(ARR_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bignatHelper);
        tmpBignatSmall2 = new Bignat(ARR_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bignatHelper);
        tmpBignatBig = new Bignat((short) (ARR_SIZE * 2), JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bignatHelper);
        SGN = new Bignat((short) (ARR_SIZE * 2), JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bignatHelper);
        clientSignature = new Bignat(ARR_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bignatHelper);

        tmpBuffer = JCSystem.makeTransientByteArray(ARR_SIZE, JCSystem.CLEAR_ON_RESET);

        serverRsaPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_2048);
        serverPrivateKey = (RSAPrivateKey) serverRsaPair.getPrivate();
        serverPublicKey = (RSAPublicKey) serverRsaPair.getPublic();

        clientPrivateKey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_2048,false);
        clientPublicKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_2048,false);

        rsaClient = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
        rsaClientVerify = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
        rsaServer = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);

        register();
    }

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

            case INS_GET_PUBLIC_N:
                getPublicModulus(apdu);
                break;

            case INS_RESET:
                reset(apdu);
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

            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void getFinalSignature(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        if (apduBuffer[ISO7816.OFFSET_P1] != 0x00)
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

        // TODO: check that is has been received + SGN
        // TODO: check part
        switch (apduBuffer[ISO7816.OFFSET_P2]) {
            case Common.P2_PART_0:
                Common.sendNum(apdu, SGN.as_byte_array(), (short) 0, false);
                break;

            case Common.P2_PART_1:
                Common.sendNum(apdu, SGN.as_byte_array(), ARR_SIZE, false);
                break;

            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }


        // after check
        // tmpBignatBig.erase();
    }


    /**
     *
     * @param apdu
     */
    private void generateRSAKeys(APDU apdu) {
        Common.checkZeroP1P2(apdu.getBuffer());

        if (serverPrivateKey.isInitialized() || serverPublicKey.isInitialized())
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);

        serverPublicKey.setExponent(E, (short) 0, (short) E.length);
        serverRsaPair.genKeyPair();

        clientPublicKey.setExponent(E, (short) 0, (short) E.length);

        rsaServer.init(serverPrivateKey, Cipher.MODE_DECRYPT);
    }

    /**
     *
     * @param apdu
     */
    private void setClientKeys(APDU apdu) {
        if (!serverPrivateKey.isInitialized() || clientPrivateKey.isInitialized())
                ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);

        byte[] apduBuffer = apdu.getBuffer();
        switch (apduBuffer[ISO7816.OFFSET_P1]) {
            case P1_SET_D1_SERVER:
                if (keyState[P1_SET_D1_SERVER] == Common.DATA_LOADED)
                    ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);

                Common.setNumber(apdu, tmpBuffer);
                updateKey(apdu);
                break;

            case P1_SET_N1:
                if (keyState[P1_SET_D1_SERVER] != Common.DATA_LOADED)
                    ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);

                if (keyState[P1_SET_N1] == Common.DATA_LOADED)
                    ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);

                Common.setNumber(apdu, tmpBuffer);
                updateKey(apdu);
                break;

            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    private void updateKey(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        byte p1 = apduBuffer[ISO7816.OFFSET_P1];
        byte p2 = apduBuffer[ISO7816.OFFSET_P2];

        if (p1 != P1_SET_D1_SERVER && p1 != P1_SET_N1)
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

        keyState[p1] = Common.updateLoadState(keyState[p1], p2);
        if (keyState[p1] != Common.DATA_LOADED)
            return;

        if (p1 == P1_SET_D1_SERVER)
            clientPrivateKey.setExponent(tmpBuffer, (short) 0, (short) tmpBuffer.length);
        else {
            clientPrivateKey.setModulus(tmpBuffer, (short) 0, (short) tmpBuffer.length);
            clientPublicKey.setModulus(tmpBuffer, (short) 0, (short) tmpBuffer.length);
        }

        if (clientPrivateKey.isInitialized())
            rsaClient.init(clientPrivateKey, Cipher.MODE_DECRYPT);

        if (clientPublicKey.isInitialized())
            rsaClientVerify.init(clientPublicKey, Cipher.MODE_ENCRYPT);

        Common.clearByteArray(tmpBuffer);
    }

    // TODO:
    private void reset(APDU apdu) {
        Common.checkZeroP1P2(apdu.getBuffer());

        clientPrivateKey.clearKey();
        clientPublicKey.clearKey();

        serverPrivateKey.clearKey();
        serverPublicKey.clearKey();

        /*messageState = 0x00;
        nSent = false;
        d1ServerSent = false;

        Common.clearByteArray(d1ServerBuffer);*/
        Common.clearByteArray(tmpBuffer);
    }

    private void setClientSignature(APDU apdu) {
        // if (!nRetrieved)
        //     ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);

        // TODO: state check

        byte[] apduBuffer = apdu.getBuffer();
        byte p1 = apduBuffer[ISO7816.OFFSET_P1];
        switch (p1) {
            case P1_SET_MESSAGE:
                if (sigState[P1_SET_MESSAGE] == Common.DATA_LOADED)
                    ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);

                Common.setNumber(apdu, tmpBuffer);
                break;

            case P1_SET_SIGNATURE:
                if (sigState[P1_SET_MESSAGE] != Common.DATA_LOADED)
                    ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);

                if (sigState[P1_SET_SIGNATURE] == Common.DATA_LOADED)
                    ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);

                Common.setNumber(apdu, clientSignature.as_byte_array());
                break;

            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        sigState[p1] = Common.updateLoadState(sigState[p1], apduBuffer[ISO7816.OFFSET_P2]);
    }

    private void getPublicModulus(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        if (apduBuffer[ISO7816.OFFSET_P1] != 0x00)
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

        // TODO: check that is has been received

        // tmpBignatBig is empty iff this method is invoked for the first time
        if (tmpBignatBig.is_zero()) {
            clientPrivateKey.getModulus(tmpBignatSmall1.as_byte_array(), (short) 0);
            serverPrivateKey.getModulus(tmpBignatSmall2.as_byte_array(), (short) 0);

            if (!isComprime(tmpBignatSmall1, tmpBignatSmall2, bignatHelper))
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);

            tmpBignatBig.mult(tmpBignatSmall2, tmpBignatSmall1);

            // 4096-bit modulus check
            if ((tmpBignatBig.as_byte_array()[0] & 0x80) != 0x80)
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);

            tmpBignatSmall1.erase();
            tmpBignatSmall2.erase();
        }

        //TODO: check part
        switch (apduBuffer[ISO7816.OFFSET_P2]) {
            case Common.P2_PART_0:
                Common.sendNum(apdu, tmpBignatBig.as_byte_array(), (short) 0, false);
                break;

            case Common.P2_PART_1:
                Common.sendNum(apdu, tmpBignatBig.as_byte_array(), ARR_SIZE, false);
                break;

            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }


        // after check
        // tmpBignatBig.erase();
    }

    private void signRSAMessage(APDU apdu) {

        // TODO test na nulovost!!!

        // TODO init elsewhere
        Bignat n1 = new Bignat(ARR_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bignatHelper);
        Bignat n2 = new Bignat(ARR_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bignatHelper);
        Bignat s1 = new Bignat(ARR_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bignatHelper);
        Bignat s2 = new Bignat(ARR_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bignatHelper);
        Bignat tmp = new Bignat(ARR_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bignatHelper);


        rsaClient.doFinal(tmpBuffer, (short) 0, (short) tmpBuffer.length, tmpBignatSmall1.as_byte_array(), (short) 0);
        clientPrivateKey.getModulus(n1.as_byte_array(), (short) 0);

        s1.mod_mult(clientSignature, tmpBignatSmall1, n1);

        rsaClientVerify.doFinal(s1.as_byte_array(), (short) 0, (short) s1.as_byte_array().length, tmpBignatSmall1.as_byte_array(), (short) 0);

        tmp.from_byte_array(tmpBuffer);

        if (!tmpBignatSmall1.same_value(tmp))
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);


        rsaServer.doFinal(tmpBuffer, (short) 0, (short) tmpBuffer.length, s2.as_byte_array(), (short) 0);

        serverPrivateKey.getModulus(n2.as_byte_array(), (short) 0);

        inverse(n1, n2, tmp, bignatHelper);

        s2.mod_sub(s1, n2);
        tmpBignatBig.mod_mult(s2, tmp, n2);
        SGN.mult(tmpBignatBig, n1);
        SGN.add(s1);

        /*
        // Compute the full signature
        Bignum s = Bignum::mod_exp(m, d2, n2) - s1;
        s.mod_mul_self(Bignum::inverse(n1, n2), n2);
        s *= n1;
        s += s1;
        */
    }

    /**
     * TODO:
     * @param a
     * @param b
     * @return
     */
    public static boolean isComprime(Bignat a, Bignat b, Bignat_Helper bh) {
        Bignat newA = new Bignat(ARR_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bh);
        Bignat newB = new Bignat(ARR_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bh);

        Bignat tmp = new Bignat(ARR_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bh);

        newA.copy(a);
        newB.copy(b);

        //TODO: nicer
        while (!newB.is_zero()) {
            tmp.clone(newB);
            newA.mod(newB);
            newB.clone(newA);
            newA.clone(tmp);
        }

        return newA.same_value(Bignat_Helper.ONE);
    }

    /**
     * TODO:
     * @param a
     * @param n
     * @param bh
     * @return
     */
    public static void inverse(Bignat a, Bignat n, Bignat res, Bignat_Helper bh) {
        Bignat t = new Bignat(ARR_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bh);
        Bignat r = new Bignat(ARR_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bh);
        Bignat newT = new Bignat(ARR_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bh);
        Bignat newR = new Bignat(ARR_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bh);

        Bignat quotient = new Bignat(ARR_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bh);

        Bignat bak = new Bignat(ARR_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bh);
        Bignat helper = new Bignat((short) (ARR_SIZE*2), JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bh);

        r.copy(n);
        newT.one();
        newR.copy(a);

        if (r.lesser(newR))
            newR.subtract(r);

        // true +/0; false -
        boolean tSgn = true;
        boolean rSgn = true;
        boolean newTSgn = true;
        boolean newRSgn = true;
        boolean quotientSgn = true;
        boolean bakSgn = true;
        boolean helperSgn = true;

//    function inverse(a, n)
//    t := 0;     newt := 1;
//    r := n;     newr := a;
//    while newr ≠ 0
//        quotient := r div newr
//        (t, newt) := (newt, t - quotient * newt)
//        (r, newr) := (newr, r - quotient * newr)
//    if r > 1 then return "a is not invertible"
//    if t < 0 then t := t + n
//    return t


        while (!newR.is_zero()) {
            helper.copy(r);
            helper.remainder_divide(newR, quotient);
            quotientSgn = rSgn == newRSgn || quotient.is_zero();

            bak.copy(newT);
            bakSgn = newTSgn;

            helper.mult(quotient, newT);
            helperSgn = quotientSgn == newTSgn || helper.is_zero();

            newT.copy(t);
            newTSgn = tSgn;

            t.clone(bak);
            tSgn = bakSgn;

            if (newT.lesser(helper) && newTSgn && helperSgn) {
                newTSgn = false;
                helper.subtract(newT);
                newT.copy(helper);
            } else if (newT.lesser(helper) && !newTSgn && !helperSgn) {
                newTSgn = true;
                helper.subtract(newT);
                newT.copy(helper);
            } else if (newTSgn == helperSgn)
                newT.subtract(helper);
            else
                newT.add(helper);

            if (newT.is_zero())
                newTSgn = true;

            bak.copy(newR);
            bakSgn = newRSgn;

            helper.mult(quotient, newR);
            helperSgn = quotientSgn == newRSgn || helper.is_zero();

            newR.copy(r);
            newRSgn = rSgn;

            r.clone(bak);
            rSgn = bakSgn;

            if (newR.lesser(helper) && newRSgn && helperSgn) {
                newRSgn = false;
                helper.subtract(newR);
                newR.copy(helper);
            } else if (newR.lesser(helper) && !newRSgn && !helperSgn) {
                newRSgn = true;
                helper.subtract(newR);
                newR.copy(helper);
            } else if (newRSgn == helperSgn)
                newR.subtract(helper);
            else
                newR.add(helper);

            if (newR.is_zero())
                newRSgn = true;
        }

        if (!r.lesser(Bignat_Helper.ONE) && !r.same_value(Bignat_Helper.ONE) && rSgn)
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);

        if (!tSgn) {
            bak.copy(n);
            bak.subtract(t);
            t.copy(bak);
        }

        res.copy(t);
    }

}
