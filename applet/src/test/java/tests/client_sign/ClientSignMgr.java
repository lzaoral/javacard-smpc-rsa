package tests.client_sign;

import smpc_rsa.RSAClientSign;

import cardTools.Util;

import tests.AbstractMgr;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;

import java.math.BigInteger;
import java.util.List;

/**
 * Instruction handler of the {@link RSAClientSign} applet
 * Note: If simulator cannot be started try adding "-noverify" JVM parameter
 *
 * @author based on work by Petr Svenda, Dusan Klinec (ph4r05)
 * @author Lukas Zaoral
 */
public class ClientSignMgr extends AbstractMgr {

    public static final byte CLA_RSA_SMPC_CLIENT_SIGN = (byte) 0x80;

    public static final byte INS_SET_KEYS = 0x10;
    public static final byte INS_SET_MESSAGE = 0x12;
    public static final byte INS_SIGNATURE = 0x14;
    public static final byte INS_RESET = 0x16;

    public static final byte P1_SET_D = 0x00;
    public static final byte P1_SET_N = 0x01;

    public static final String APPLET_AID = "0102030405060708090102";

    /**
     * Creates connection to the {@link RSAClientSign} applet
     *
     * @param realCard decides whether to use real card or emulator
     * @throws Exception if card error occurs
     */
    public ClientSignMgr(boolean realCard) throws Exception {
        super(APPLET_AID, RSAClientSign.class, realCard);
    }

    /**
     * Sets client keys
     *
     * @throws Exception if IO or card error occurs
     */
    public void setKeys() throws Exception {
        List<CommandAPDU> setDcmd;
        List<CommandAPDU> setNcmd;

        try (InputStream in = new FileInputStream(CLIENT_KEYS_CLIENT_FILE_PATH)) {
            BufferedReader reader = new BufferedReader(new InputStreamReader(in));

            byte[] num = Util.hexStringToByteArray(reader.readLine());
            BigInteger d = new BigInteger(1, num);

            setDcmd = setNumber(num, CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_KEYS, P1_SET_D);

            num = Util.hexStringToByteArray(reader.readLine());
            BigInteger n = new BigInteger(1, num);

            if (num.length != ARR_LENGTH)
                throw new IllegalArgumentException("Modulus is not a 256-bit number.");

            if (d.compareTo(n) > 0)
                throw new IllegalArgumentException("Private key cannot be larger than modulus.");

            setNcmd = setNumber(num, CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_KEYS, P1_SET_N);

            if (reader.readLine() != null)
                throw new IOException(String.format("Wrong '%s' file format.", CLIENT_KEYS_CLIENT_FILE_PATH));
        }

        transmitNumber(setDcmd, "Set D");
        transmitNumber(setNcmd, "Set N");
    }

    /**
     * Signs given message
     *
     * @return response
     * @throws Exception if IO or card error occurs
     */
    public ResponseAPDU signMessage() throws Exception {
        String message;
        List<CommandAPDU> messageCmd;

        try (InputStream in = new FileInputStream(MESSAGE_FILE_PATH)) {
            BufferedReader reader = new BufferedReader(new InputStreamReader(in));

            message = reader.readLine();
            byte[] num = Util.hexStringToByteArray(message);

            if (num.length > ARR_LENGTH)
                throw new IllegalArgumentException("Message key cannot be larger than modulus.");

            messageCmd = setNumber(num, CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_MESSAGE, NONE);

            if (reader.readLine() != null)
                throw new IOException(String.format("Wrong '%s' file format.", MESSAGE_FILE_PATH));
        }

        transmitNumber(messageCmd, "Set message");
        ResponseAPDU res = transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SIGNATURE, NONE, NONE, ARR_LENGTH
        ));
        handleError(res, "Signing");

        try (OutputStream out = new FileOutputStream(CLIENT_SIG_SHARE_FILE_PATH)) {
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(out));
            writer.write(String.format(
                    "%s%n%s%n", message, Util.toHex(res.getData())
            ));
            writer.flush();
        }

        return res;
    }



}
