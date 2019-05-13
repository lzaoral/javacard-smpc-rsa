package tests.client_full;

import smpc_rsa.RSAClient;

import cardTools.CardManager;
import cardTools.RunConfig;
import cardTools.Util;

import javax.smartcardio.CardException;
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

import java.util.ArrayList;
import java.util.Arrays;

import static tests.Common.*;

/**
 * Test class.
 * Note: If simulator cannot be started try adding "-noverify" JVM parameter
 *
 * @author Petr Svenda, Dusan Klinec (ph4r05), Lukas Zaoral
 */
public class ClientFullAPDU {
    public static final byte CLA_RSA_SMPC_CLIENT = (byte) 0x90;

    public static final byte INS_GENERATE_KEYS = 0x10;
    public static final byte INS_GET_KEYS = 0x12;
    public static final byte INS_SET_MESSAGE = 0x14;
    public static final byte INS_SIGNATURE = 0x16;
    public static final byte INS_RESET = 0x18;

    public static final byte P1_GET_N = 0x00;
    public static final byte P1_GET_D1_SERVER = 0x01;

    public static final byte P2_PART_0 = 0x00;
    public static final byte P2_PART_1 = 0x01;
    public static final byte P2_SINGLE = 0x00;
    public static final byte P2_DIVIDED = 0x10;

    public static final byte NONE = 0x00;

    public static final String TEST_PATH = "src/test/java/tests/client_full/";
    public static final String CLIENT_KEY_SERVER_SHARE_FILE = TEST_PATH + CLIENT_KEYS_SERVER_FILE;
    public static final String MESSAGE_FILES = TEST_PATH + MESSAGE_FILE;
    public static final String CLIENT_SHARE_SIG_FILE = TEST_PATH + CLIENT_SIG_SHARE_FILE;

    public static final short CLIENT_ARR_LENGTH = 256;
    private static final short MAX_APDU_LENGTH = 0xFF;

    private static String APPLET_AID = "0102030405060708090203";
    private static byte[] APPLET_AID_BYTE = Util.hexStringToByteArray(APPLET_AID);

    private static final CardManager cardMgr = new CardManager(APPLET_AID_BYTE);

    /**
     *
     * @param realCard
     * @throws Exception
     */
    public ClientFullAPDU(boolean realCard) throws Exception {
        final RunConfig runCfg = RunConfig.getDefaultConfig();

        if (realCard)
            runCfg.setTestCardType(RunConfig.CARD_TYPE.PHYSICAL);
        else {
            runCfg.setAppletToSimulate(RSAClient.class)
                    .setTestCardType(RunConfig.CARD_TYPE.JCARDSIMLOCAL)
                    .setbReuploadApplet(true)
                    .setInstallData(new byte[8]);
        }

        System.out.print("Connecting to card...");
        if (!cardMgr.Connect(runCfg)) {
            System.out.println(" Fail.");
            return;
        }
        System.out.println(" Done.");
    }

    /**
     *
     *
     * @param cmds
     * @param num
     * @param ins
     * @param p1
     */
    private void setNumber(ArrayList<CommandAPDU> cmds, byte[] num, byte ins, byte p1) {
        if (num.length <= MAX_APDU_LENGTH) {
            cmds.add(new CommandAPDU(CLA_RSA_SMPC_CLIENT, ins, p1, P2_PART_0 | P2_SINGLE, num));
            return;
        }

        for (int i = num.length; i > 0; i -= MAX_APDU_LENGTH) {
            cmds.add(new CommandAPDU(
                    CLA_RSA_SMPC_CLIENT, ins, p1, (i / MAX_APDU_LENGTH > 0 ? P2_PART_0 : P2_PART_1) | P2_DIVIDED,
                    Arrays.copyOfRange(num, i - MAX_APDU_LENGTH > 0 ? i - MAX_APDU_LENGTH : 0, i)
            ));
        }
    }

    /**
     *
     * @param cmd
     * @return
     * @throws Exception
     */
    public ResponseAPDU transmit(CommandAPDU cmd) throws Exception {
        return cardMgr.transmit(cmd);
    }

    /**
     *
     * @return
     * @throws CardException
     */
    public ResponseAPDU generateKeys() throws CardException {
        ResponseAPDU res = cardMgr.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_GENERATE_KEYS, NONE, NONE
        ));

        handleError(res, "Key generation");

        return res;
    }

    /**
     *
     * @throws Exception
     */
    public void getKeys() throws Exception {
        ResponseAPDU dServer = cardMgr.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_GET_KEYS, P1_GET_D1_SERVER, NONE, CLIENT_ARR_LENGTH
        ));
        handleError(dServer, "Get d1Server");

        ResponseAPDU n = cardMgr.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_GET_KEYS, P1_GET_N, NONE, CLIENT_ARR_LENGTH
        ));
        handleError(n, "Get n");

        try (OutputStream out = new FileOutputStream(CLIENT_KEY_SERVER_SHARE_FILE)) {
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(out));

            writer.write(String.format("%s%n%s%n", Util.toHex(Util.trimLeadingZeroes(dServer.getData())),
                    Util.toHex(Util.trimLeadingZeroes(n.getData()))));

            writer.flush();
        }
    }

    public void setDebug(boolean debug) {
        cardMgr.setbDebug(debug);
    }

    /**
     *
     * @return
     * @throws Exception
     */
    public ResponseAPDU signMessage() throws Exception {
        ArrayList<CommandAPDU> APDU_MESSAGE = new ArrayList<>();
        String message;

        try (InputStream in = new FileInputStream(MESSAGE_FILES)) {
            BufferedReader reader = new BufferedReader(new InputStreamReader(in));

            message = reader.readLine();
            byte[] num = Util.hexStringToByteArray(message);

            // TODO, > comparison
            if (num.length > CLIENT_ARR_LENGTH)
                throw new IllegalArgumentException("Message key cannot be longer than modulus.");

            setNumber(APDU_MESSAGE, num, INS_SET_MESSAGE, NONE);

            if (reader.readLine() != null)
                throw new IOException(String.format("Wrong '%s' file format.", MESSAGE_FILE));
        }

        for (CommandAPDU cmd : APDU_MESSAGE)
            handleError(transmit(cmd), "Set message");

        ResponseAPDU res = cardMgr.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SIGNATURE, NONE, NONE, CLIENT_ARR_LENGTH
        ));
        handleError(res, "Signing");

        String data = Util.toHex(Util.trimLeadingZeroes(res.getData()));

        try (OutputStream out = new FileOutputStream(CLIENT_SHARE_SIG_FILE)) {
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(out));
            writer.write(String.format("%s%n%s%n", message, data));
            writer.flush();
        }

        return res;
    }

    /**
     *
     * @param res
     * @param operation
     * @throws CardException
     */
    private void handleError(ResponseAPDU res, String operation) throws CardException {
        if (res.getSW() != 0x9000)
            throw new CardException(String.format("%s: %d", operation, res.getSW()));
    }

}
