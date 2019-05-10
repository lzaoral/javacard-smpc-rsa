package tests.server;

import cardTools.CardManager;
import cardTools.RunConfig;
import cardTools.Util;

import smpc_rsa.RSAServer;

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
import java.util.Arrays;

/**
 * Test class.
 * Note: If simulator cannot be started try adding "-noverify" JVM parameter
 *
 * @author Petr Svenda, Dusan Klinec (ph4r05)
 */
public class ServerAPDU {
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

    public static final byte P2_PART_0 = 0x00;
    public static final byte P2_PART_1 = 0x01;
    public static final byte P2_SINGLE = 0x00;
    public static final byte P2_DIVIDED = 0x10;

    public static final byte NONE = 0x00;

    public static final short CLIENT_ARR_LENGTH = 256;
    private static final short MAX_APDU_LENGTH = 0xFF;

    public static final String TEST_PATH = "src/test/java/tests/server/";
    public static final String CLIENT_KEY_SERVER_SHARE_FILE = TEST_PATH + "for_server.key";
    public static final String MESSAGE_FILE = TEST_PATH + "message.txt";
    public static final String CLIENT_SHARE_SIG_FILE = TEST_PATH + "client.sig";
    public static final String PUBLIC_KEY_FILE = TEST_PATH + "public.key";
    public static final String FINAL_SIG_FILE = TEST_PATH + "final.sig";

    private static String APPLET_AID = "0102030405060708090304";
    private static byte[] APPLET_AID_BYTE = Util.hexStringToByteArray(APPLET_AID);

    private static final CardManager cardMgr = new CardManager(APPLET_AID_BYTE);

    /**
     *
     * @param realCard
     * @throws Exception
     */
    public ServerAPDU(boolean realCard) throws Exception {
        final RunConfig runCfg = RunConfig.getDefaultConfig();

        if (realCard)
            runCfg.setTestCardType(RunConfig.CARD_TYPE.PHYSICAL);
        else {
            runCfg.setAppletToSimulate(RSAServer.class)
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

    public ResponseAPDU transmit(CommandAPDU cmd) throws Exception {
        return cardMgr.transmit(cmd);
    }

    public ResponseAPDU generateKeys() throws Exception {
        //TODO:

        return transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_GENERATE_KEYS, 0x00, 0x00
        ));
    }

    public void setClientKeys() throws Exception {
        ArrayList<CommandAPDU> APDU_SET_D1_SERVER = new ArrayList<>();
        ArrayList<CommandAPDU> APDU_SET_N1 = new ArrayList<>();

        try (InputStream in = new FileInputStream(CLIENT_KEY_SERVER_SHARE_FILE)) {
            BufferedReader reader = new BufferedReader(new InputStreamReader(in));

            byte[] num = Util.hexStringToByteArray(reader.readLine());
            BigInteger d = new BigInteger(1, num);

            setNumber(APDU_SET_D1_SERVER, num, INS_SET_CLIENT_KEYS, P1_SET_D1_SERVER);

            num = Util.hexStringToByteArray(reader.readLine());
            BigInteger n = new BigInteger(1, num);

            if (num.length != CLIENT_ARR_LENGTH)
                throw new IllegalArgumentException("Modulus is not a 256-bit number.");

            if (d.compareTo(n) > 0)
                throw new IllegalArgumentException("Private key cannot be larger than modulus.");

            setNumber(APDU_SET_N1, num, INS_SET_CLIENT_KEYS, P1_SET_N1);

            if (reader.readLine() != null)
                throw new IOException(String.format("Wrong '%s' file format.", CLIENT_KEY_SERVER_SHARE_FILE));
        }

        transmitNumber(APDU_SET_D1_SERVER);
        transmitNumber(APDU_SET_N1);
    }

    /**
     *
     * @param cmd
     * @throws Exception
     */
    private void transmitNumber(ArrayList<CommandAPDU> cmd) throws Exception {
        for (CommandAPDU c : cmd) {
            transmit(c);
        }
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
            cmds.add(new CommandAPDU(CLA_RSA_SMPC_SERVER, ins, p1, P2_PART_0 | P2_SINGLE, num));
            return;
        }

        for (int i = num.length; i > 0; i -= MAX_APDU_LENGTH) {
            cmds.add(new CommandAPDU(
                    CLA_RSA_SMPC_SERVER, ins, p1, (i / MAX_APDU_LENGTH > 0 ? P2_PART_0 : P2_PART_1) | P2_DIVIDED,
                    Arrays.copyOfRange(num, i - MAX_APDU_LENGTH > 0 ? i - MAX_APDU_LENGTH : 0, i)
            ));
        }
    }

    public ArrayList<ResponseAPDU> getPublicModulus() throws Exception {
        ArrayList<ResponseAPDU> res = new ArrayList<>();

        // zjednodusit
        res.add(transmit(new CommandAPDU(
            CLA_RSA_SMPC_SERVER, INS_GET_PUBLIC_N, 0x00, P2_PART_0
        )));

        res.add(transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_GET_PUBLIC_N, 0x00, P2_PART_1
        )));

        try (OutputStream out = new FileOutputStream(PUBLIC_KEY_FILE)) {
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(out));
            writer.write(String.format("%s%n", "10001")); //todo hardcoded E
            for (ResponseAPDU r: res) {
                writer.write(Util.toHex(r.getData()));
            }
            writer.write(System.lineSeparator());
            writer.flush();
        }

        return res;
    }

    public ResponseAPDU signMessage() throws Exception {
        ArrayList<CommandAPDU> APDU_SET_MESSAGE = new ArrayList<>();
        ArrayList<CommandAPDU> APDU_SET_CLIENT_SIGNATURE = new ArrayList<>();
        String message;

        try (InputStream in = new FileInputStream(CLIENT_SHARE_SIG_FILE)) {
            BufferedReader reader = new BufferedReader(new InputStreamReader(in));

            message = reader.readLine();
            byte[] num = Util.hexStringToByteArray(message);

            if (num.length > CLIENT_ARR_LENGTH)
                throw new IllegalArgumentException("Message cannot be larger than the modulus.");

            setNumber(APDU_SET_MESSAGE, num, INS_SET_CLIENT_SIGNATURE, P1_SET_MESSAGE);

            num = Util.hexStringToByteArray(reader.readLine());

            if (num.length > CLIENT_ARR_LENGTH)
                throw new IllegalArgumentException("Client signature share cannot be larger than the modulus.");

            setNumber(APDU_SET_CLIENT_SIGNATURE, num, INS_SET_CLIENT_SIGNATURE, P1_SET_SIGNATURE);

            if (reader.readLine() != null)
                throw new IOException(String.format("Wrong '%s' file format.", CLIENT_SHARE_SIG_FILE));
        }

        transmitNumber(APDU_SET_MESSAGE);
        transmitNumber(APDU_SET_CLIENT_SIGNATURE);

        ResponseAPDU res = transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SIGNATURE, NONE, NONE
        ));

        //response check

        ArrayList<ResponseAPDU> responses = new ArrayList<>();
        responses.add(transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_GET_SIGNATURE, 0x00, P2_PART_0
        )));

        responses.add(transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_GET_SIGNATURE, 0x00, P2_PART_1
        )));

        try (OutputStream out = new FileOutputStream(FINAL_SIG_FILE)) {
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
