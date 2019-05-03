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
    private static final byte P1_SET_N1 = 0x11;
    private static final byte P1_SET_D1_SERVER = 0x12;
    private static final byte INS_GET_PUBLIC_N = 0x14;
    private static final byte INS_SET_CLIENT_SIGNATURE = 0x16;

    private static final byte P1_SET_MESSAGE = 0x05;
    private static final byte P1_SET_SIGNATURE = 0x06;

    private static final byte INS_SIGNATURE = 0x18;

    //TODO: reset

    private static boolean generatedKeys = false;
    private static final short ARR_SIZE = 256;

    private static final byte[] E = new byte[]{0x01, 0x00, 0x01};

    private final Bignat tmpBignatSmall1, tmpBignatSmall2, tmpBignatBig, clientSignature;

    private final Bignat SGN;
    private byte[] tmpBuffer;

    private final ECConfig jcMathCfg;
    private final Bignat_Helper bignatHelper;

    private final KeyPair clientRsaPair;
    private final RSAPrivateKey clientPrivateKey;
    private final RSAPublicKey clietPublicKey;

    private final KeyPair serverRsaPair;
    private final RSAPrivateKey serverPrivateKey;
    private final RSAPublicKey serverPublicKey;

    private final Cipher rsa;

    private final byte[] keyState = new byte[2];
    private final byte[] sigState = new byte[2];

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new RSAServer(bArray, bOffset, bLength);
    }

    public RSAServer(byte[] buffer, short offset, byte length) {
        jcMathCfg = new ECConfig(ARR_SIZE);
        bignatHelper = jcMathCfg.bnh;

        tmpBignatSmall1 = new Bignat(ARR_SIZE, JCSystem.MEMORY_TYPE_PERSISTENT, bignatHelper);
        tmpBignatSmall2 = new Bignat(ARR_SIZE, JCSystem.MEMORY_TYPE_PERSISTENT, bignatHelper);
        tmpBignatBig = new Bignat((short) (ARR_SIZE * 2), JCSystem.MEMORY_TYPE_PERSISTENT, bignatHelper);
        SGN = new Bignat((short) (ARR_SIZE * 2), JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bignatHelper);
        clientSignature = new Bignat(ARR_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bignatHelper);

        tmpBuffer = JCSystem.makeTransientByteArray(ARR_SIZE, JCSystem.CLEAR_ON_RESET);

        serverRsaPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_2048);
        serverPrivateKey = (RSAPrivateKey) serverRsaPair.getPrivate();
        serverPublicKey = (RSAPublicKey) serverRsaPair.getPublic();
        serverPublicKey.setExponent(E, (short) 0, (short) E.length);

        clientRsaPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_2048);
        clientPrivateKey = (RSAPrivateKey) clientRsaPair.getPrivate();
        clietPublicKey = (RSAPublicKey) clientRsaPair.getPublic();
        clientPrivateKey.setExponent(E, (short) 0, (short) E.length);

        rsa = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);

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

            case INS_SET_CLIENT_SIGNATURE:
                setClientSignature(apdu);
                break;

            case INS_SIGNATURE:
                signRSAMessage(apdu);
                break;

            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }



    private void generateRSAKeys(APDU apdu) {
        Common.checkZeroP1P2(apdu.getBuffer());

        if (serverPrivateKey.isInitialized())
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);

        // this should never happen
        if (!serverPublicKey.isInitialized())
            ISOException.throwIt(ISO7816.SW_UNKNOWN);

        byte[] apduBuffer = apdu.getBuffer();
        Common.checkZeroP1P2(apduBuffer);

        serverRsaPair.genKeyPair();
    }

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
        else
            clientPrivateKey.setModulus(tmpBuffer, (short) 0, (short) tmpBuffer.length);

        if (clientPrivateKey.isInitialized())
            rsa.init(clientPrivateKey, Cipher.MODE_DECRYPT);

        Common.clearByteArray(tmpBuffer);
    }

    private void setClientSignature(APDU apdu) {
        // if (!nRetrieved)
        //     ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);

        byte[] apduBuffer = apdu.getBuffer();
        byte p1 = apduBuffer[ISO7816.OFFSET_P1];
        byte p2 = apduBuffer[ISO7816.OFFSET_P2];
        switch (p1) {
            case P1_SET_SIGNATURE:
                if (keyState[P1_SET_SIGNATURE] == Common.DATA_LOADED)
                    ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);

                Common.setNumber(apdu, clientSignature.as_byte_array());
                updateKey(apdu);
                break;

            case P1_SET_MESSAGE:
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

        keyState[p1] = Common.updateLoadState(keyState[p1], p2);
    }

    private void getPublicModulus(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        if (apduBuffer[ISO7816.OFFSET_P1] != 0x00)
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

        // do only once
        clientPrivateKey.getModulus(tmpBignatSmall1.as_byte_array(), (short) 0);
        serverPrivateKey.getModulus(tmpBignatBig.as_byte_array(), (short) 0);

        if (!isComprime(tmpBignatSmall1, tmpBignatBig, bignatHelper))
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);

        tmpBignatBig.mult(tmpBignatBig, tmpBignatSmall1);
        tmpBignatSmall1.erase();
        // do only once

        //TODO: check part
        switch (apduBuffer[ISO7816.OFFSET_P2]) {
            case Common.P2_PART_0:
                Common.sendNum(apdu, tmpBignatBig.as_byte_array(), (short) 0, false);
                break;

            case Common.P2_PART_1:
                Common.sendNum(apdu, tmpBignatBig.as_byte_array(), (short) 255, false);
                break;

            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }


        // after check
        // tmpBignatBig.erase();
    }

    private void signRSAMessage(APDU apdu) {
        // TODO init elsewhere
        rsa.init(clientPrivateKey, Cipher.MODE_DECRYPT);
        rsa.doFinal(tmpBuffer, (short) 0, (short) tmpBuffer.length, tmpBignatSmall1.as_byte_array(), (short) 0);

        clientSignature.mult(clientSignature, tmpBignatSmall1);

        rsa.init(clietPublicKey, Cipher.MODE_ENCRYPT);
        rsa.doFinal(tmpBignatSmall1.as_byte_array(), (short) 0, tmpBignatSmall1.length(), tmpBignatSmall2.as_byte_array(), (short) 0);

        tmpBignatSmall2.from_byte_array(tmpBuffer);

        // nebude fungovat, blba velikost
        if (!tmpBignatSmall1.same_value(tmpBignatSmall2))
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);

        rsa.init(serverPrivateKey, Cipher.MODE_DECRYPT);
        rsa.doFinal(tmpBuffer, (short) 0, (short) tmpBuffer.length, tmpBignatBig.as_byte_array(), (short) 255);

        serverPrivateKey.getExponent(tmpBignatSmall2.as_byte_array(), (short) 0);
        serverPrivateKey.getModulus(tmpBignatBig.as_byte_array(), (short) 255);

        SGN.subtract(tmpBignatSmall1);
        SGN.mod_mult(SGN, inverse(tmpBignatSmall2, tmpBignatBig, bignatHelper), tmpBignatBig);
        SGN.mult(SGN, tmpBignatBig);
        SGN.add(tmpBignatSmall1);


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

        newA.copy(a);
        newB.copy(b);

        while (!newA.same_value(newB)) {
            if (!newA.smaller(newB))
                newA.subtract(newB);
            else
                newB.subtract(newA);
        }

        return newA.is_zero();
    }

    /**
     * TODO:
     * @param a
     * @param n
     * @param bh
     * @return
     */
    public static Bignat inverse(Bignat a, Bignat n, /*Bignat res,*/ Bignat_Helper bh) {
        Bignat t = new Bignat(ARR_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bh);
        Bignat r = new Bignat(ARR_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bh);
        Bignat newT = new Bignat(ARR_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bh);
        Bignat newR = new Bignat(ARR_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bh);

        Bignat quotient = new Bignat(ARR_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bh);

        Bignat bak = new Bignat(ARR_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bh);
        Bignat helper = new Bignat(ARR_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, bh);

        r.clone(n);
        newT.one();
        newR.clone(a);

        while (!newR.is_zero()) {
            quotient.remainder_divide(r, newR);

            bak.clone(newR);
            helper.mult(quotient, newR);
            newR.clone(r);
            newR.subtract(helper);
            t.clone(bak);

            bak.clone(newT);
            helper.mult(quotient, newT);
            newT.clone(t);
            newT.subtract(helper);
            t.clone(bak);
        }

        helper.one();
        if (r.lesser(helper) || r.same_value(helper))
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);

        if (t.lesser(helper))
            t.add(n);

        return t;
        //res.clone(t);
        //return res;
    }

}
