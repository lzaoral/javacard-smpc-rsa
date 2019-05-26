package tests.server;

import cardTools.Util;

import smpc_rsa.RSAServer;

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

import java.util.ArrayList;
import java.util.List;

/**
 * Instruction handler of the {@link RSAServer} applet
 * Note: If simulator cannot be started try adding "-noverify" JVM parameter
 *
 * @author based on work by Petr Svenda, Dusan Klinec (ph4r05)
 * @author Lukas Zaoral
 */
public class ServerMgr extends AbstractMgr {

    public static final byte CLA_RSA_SMPC_SERVER = (byte) 0x80;

    public static final byte INS_GENERATE_KEYS = 0x10;
    public static final byte INS_SET_CLIENT_KEYS = 0x12;
    public static final byte INS_GET_PUBLIC_MODULUS = 0x14;
    public static final byte INS_SET_CLIENT_SIGNATURE = 0x16;
    public static final byte INS_SIGNATURE = 0x18;
    public static final byte INS_GET_SIGNATURE = 0x20;
    public static final byte INS_RESET = 0x22;

    public static final byte P1_SET_D1_SERVER = 0x00;
    public static final byte P1_SET_N1 = 0x01;

    public static final byte P1_SET_MESSAGE = 0x00;
    public static final byte P1_SET_SIGNATURE = 0x01;

    public static final String APPLET_AID = "0102030405060708090104";

    /**
     * Creates connection to the {@link RSAServer} applet
     *
     * @param realCard decides whether to use real card or emulator
     * @throws Exception if card error occurs
     */
    public ServerMgr(boolean realCard) throws Exception {
        super(APPLET_AID, RSAServer.class, realCard);
    }

    /**
     * Generates server keys
     *
     * @throws Exception if IO or card error occurs
     */
    public ResponseAPDU generateKeys() throws Exception {
        ResponseAPDU res = transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_GENERATE_KEYS, NONE, NONE
        ));
        handleError(res, "Keygen");

        return res;
    }

    /**
     * Sets server share of client keys
     *
     * @throws Exception if IO or card error occurs
     */
    public void setClientKeys() throws Exception {
        List<CommandAPDU> setD1ServerCmd;
        List<CommandAPDU> setN1Cmd;

        try (InputStream in = new FileInputStream(CLIENT_KEYS_SERVER_FILE_PATH)) {
            BufferedReader reader = new BufferedReader(new InputStreamReader(in));

            byte[] num = Util.hexStringToByteArray(reader.readLine());
            BigInteger d = new BigInteger(1, num);

            setD1ServerCmd = setNumber(num, CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_KEYS, P1_SET_D1_SERVER);

            num = Util.hexStringToByteArray(reader.readLine());
            BigInteger n = new BigInteger(1, num);

            if (num.length != ARR_LENGTH)
                throw new IllegalArgumentException("Modulus is not a 256-bit number.");

            if (d.compareTo(n) > 0)
                throw new IllegalArgumentException("Private key cannot be larger than modulus.");

            setN1Cmd = setNumber(num, CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_KEYS, P1_SET_N1);

            if (reader.readLine() != null)
                throw new IOException(String.format("Wrong '%s' file format.", CLIENT_KEYS_SERVER_FILE_PATH));
        }

        transmitNumber(setD1ServerCmd, "SetD1Server");
        transmitNumber(setN1Cmd, "SetN1Server");
    }

    /**
     * Gets public modulus
     *
     * @return responses
     * @throws Exception if IO or card error occurs
     */
    public List<ResponseAPDU> getPublicModulus() throws Exception {
        List<ResponseAPDU> res = new ArrayList<>();

        res.add(transmit(new CommandAPDU(CLA_RSA_SMPC_SERVER, INS_GET_PUBLIC_MODULUS, NONE, P2_PART_0)));
        res.add(transmit(new CommandAPDU(CLA_RSA_SMPC_SERVER, INS_GET_PUBLIC_MODULUS, NONE, P2_PART_1)));

        try (OutputStream out = new FileOutputStream(PUBLIC_KEY_FILE_PATH)) {
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(out));
            writer.write(String.format("%s%n", "10001")); //hardcoded E
            for (ResponseAPDU r: res) {
                writer.write(Util.toHex(r.getData()));
            }
            writer.write(System.lineSeparator());
            writer.flush();
        }

        return res;
    }

    /**
     * Computes final signature of given message
     *
     * @return response
     * @throws Exception if IO or card error occurs
     */
    public ResponseAPDU signMessage() throws Exception {
        List<CommandAPDU> messageCmd;
        List<CommandAPDU> clientSigCmd;
        String message;

        try (InputStream in = new FileInputStream(CLIENT_SIG_SHARE_FILE_PATH)) {
            BufferedReader reader = new BufferedReader(new InputStreamReader(in));

            message = reader.readLine();
            byte[] num = Util.hexStringToByteArray(message);

            if (num.length > ARR_LENGTH)
                throw new IllegalArgumentException("Message cannot be larger than the modulus.");

            messageCmd = setNumber(num, CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_SIGNATURE, P1_SET_MESSAGE);

            num = Util.hexStringToByteArray(reader.readLine());

            if (num.length > ARR_LENGTH)
                throw new IllegalArgumentException("Client signature share cannot be larger than the modulus.");

            clientSigCmd = setNumber(num, CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_SIGNATURE, P1_SET_SIGNATURE);

            if (reader.readLine() != null)
                throw new IOException(String.format("Wrong '%s' file format.", CLIENT_SIG_SHARE_FILE_PATH));
        }

        transmitNumber(messageCmd, "Set message");
        transmitNumber(clientSigCmd, "Set client signature");

        ResponseAPDU res = transmit(new CommandAPDU(CLA_RSA_SMPC_SERVER, INS_SIGNATURE, NONE, NONE));

        //response check
        ArrayList<ResponseAPDU> responses = new ArrayList<>();
        responses.add(transmit(new CommandAPDU(CLA_RSA_SMPC_SERVER, INS_GET_SIGNATURE, NONE, P2_PART_0)));
        responses.add(transmit(new CommandAPDU(CLA_RSA_SMPC_SERVER, INS_GET_SIGNATURE, NONE, P2_PART_1)));

        try (OutputStream out = new FileOutputStream(FINAL_SIG_FILE_PATH)) {
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(out));
            writer.write(String.format("%s%n", message));

            for (ResponseAPDU r:responses) {
                writer.write(Util.toHex(r.getData()));
            }

            writer.write(System.lineSeparator());
            writer.flush();
        }

        return res;
    }

}
