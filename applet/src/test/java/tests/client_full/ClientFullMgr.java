package tests.client_full;

import smpc_rsa.RSAClient;

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

import java.util.List;

/**
 * Instruction handler of the {@link RSAClient} applet
 * Note: If simulator cannot be started try adding "-noverify" JVM parameter
 *
 * @author based on work by Petr Svenda, Dusan Klinec (ph4r05)
 * @author Lukas Zaoral
 */
public class ClientFullMgr extends AbstractMgr {

    public static final byte CLA_RSA_SMPC_CLIENT = (byte) 0x80;

    public static final byte INS_GENERATE_KEYS = 0x10;
    public static final byte INS_GET_KEYS = 0x12;
    public static final byte INS_SET_MESSAGE = 0x14;
    public static final byte INS_SIGNATURE = 0x16;
    public static final byte INS_RESET = 0x18;

    public static final byte P1_GET_D1_SERVER = 0x00;
    public static final byte P1_GET_N = 0x01;

    public static final String APPLET_AID = "0102030405060708090103";

    /**
     * Creates connection to the {@link RSAClient} applet
     *
     * @param realCard decides whether to use real card or emulator
     * @throws Exception if card error occurs
     */
    public ClientFullMgr(boolean realCard) throws Exception {
       super(APPLET_AID, RSAClient.class, realCard);
    }

    /**
     * Generates client keys
     *
     * @throws Exception if card error occurs
     */
    public ResponseAPDU generateKeys() throws Exception {
        ResponseAPDU res = transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_GENERATE_KEYS, NONE, NONE
        ));

        handleError(res, "Key generation");

        return res;
    }

    /**
     * Gets server share of client keys
     *
     * @throws Exception if IO or card error occurs
     */
    public void getKeys() throws Exception {
        ResponseAPDU dServer = transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_GET_KEYS, P1_GET_D1_SERVER, NONE, ARR_LENGTH
        ));
        handleError(dServer, "Get d1Server");

        ResponseAPDU n = transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_GET_KEYS, P1_GET_N, NONE, ARR_LENGTH
        ));
        handleError(n, "Get n");

        try (OutputStream out = new FileOutputStream(CLIENT_KEYS_SERVER_FILE_PATH)) {
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(out));

            writer.write(String.format("%s%n%s%n", Util.toHex(dServer.getData()),
                    Util.toHex(n.getData())));

            writer.flush();
        }
    }

    /**
     * Signs given message
     *
     * @return response
     * @throws Exception if IO or card error occurs
     */
    public ResponseAPDU signMessage() throws Exception {
        List<CommandAPDU> messageCmd;
        String message;

        try (InputStream in = new FileInputStream(MESSAGE_FILE_PATH)) {
            BufferedReader reader = new BufferedReader(new InputStreamReader(in));

            message = reader.readLine();
            byte[] num = Util.hexStringToByteArray(message);

            if (num.length > ARR_LENGTH)
                throw new IllegalArgumentException("Message key cannot be longer than modulus.");

            messageCmd = setNumber(num, CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, NONE);

            if (reader.readLine() != null)
                throw new IOException(String.format("Wrong '%s' file format.", MESSAGE_FILE_PATH));
        }

        for (CommandAPDU cmd : messageCmd)
            handleError(transmit(cmd), "Set message");

        ResponseAPDU res = transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SIGNATURE, NONE, NONE, ARR_LENGTH
        ));
        handleError(res, "Signing");

        try (OutputStream out = new FileOutputStream(CLIENT_SIG_SHARE_FILE_PATH)) {
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(out));
            writer.write(String.format("%s%n%s%n", message, Util.toHex(res.getData())));
            writer.flush();
        }

        return res;
    }

}
