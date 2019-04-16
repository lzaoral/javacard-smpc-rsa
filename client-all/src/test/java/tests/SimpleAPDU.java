package tests;

import applet.RSAClient;

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

/**
 * Test class.
 * Note: If simulator cannot be started try adding "-noverify" JVM parameter
 *
 * @author Petr Svenda, Dusan Klinec (ph4r05)
 */
public class SimpleAPDU {
    private static final byte RSA_SMPC_CLIENT = 0x1C;

    private static final byte NONE = 0x00;

    private static final byte GENERATE_KEYS = 0x10;

    private static final byte SET_MESSAGE = 0x11;
    private static final byte PART_0 = 0x00;
    private static final byte PART_1 = 0x01;

    private static final byte GET_KEYS = 0x15;
    private static final byte GET_N = 0x00;
    private static final byte GET_D_SERVER = 0x01;

    private static final byte SIGNATURE = 0x20;

    private static final byte TEST = 0x30;


    private static final short CLIENT_KEY_BYTE_LENGTH = 256;

    private static final boolean realCard = true;
    private static final boolean debug = false;

    private static String APPLET_AID = "0102030405060708090102";
    private static byte[] APPLET_AID_BYTE = Util.hexStringToByteArray(APPLET_AID);

    private static final CommandAPDU APDU_GENERATE_KEYS = new CommandAPDU(RSA_SMPC_CLIENT, GENERATE_KEYS, NONE, NONE);
    private static final CommandAPDU APDU_GET_N = new CommandAPDU(RSA_SMPC_CLIENT, GET_KEYS, GET_N, NONE, CLIENT_KEY_BYTE_LENGTH);
    private static final CommandAPDU APDU_GET_D_SERVER = new CommandAPDU(RSA_SMPC_CLIENT, GET_KEYS, GET_D_SERVER, NONE, CLIENT_KEY_BYTE_LENGTH);

    private static final ArrayList<CommandAPDU> APDU_MESSAGE = new ArrayList<>();
    private static final CommandAPDU APDU_SIGNATURE = new CommandAPDU(RSA_SMPC_CLIENT, SIGNATURE, NONE, NONE, CLIENT_KEY_BYTE_LENGTH);

    private static final CommandAPDU APDU_TEST = new CommandAPDU(RSA_SMPC_CLIENT, TEST, 0x0, 0x0);

    private static final CardManager cardMgr = new CardManager(APPLET_AID_BYTE, debug);

    public SimpleAPDU() throws Exception {
        final RunConfig runCfg = RunConfig.getDefaultConfig();

        if (realCard)
            runCfg.setTestCardType(RunConfig.CARD_TYPE.PHYSICAL);
        else {
            runCfg.setAppletToSimulate(RSAClient.class)
                    .setTestCardType(RunConfig.CARD_TYPE.JCARDSIMLOCAL)
                    .setbReuploadApplet(true)
                    .setInstallData(new byte[8]);
        }

        if (cardMgr.isbDebug())
            System.out.print("Connecting to card...");
        if (!cardMgr.Connect(runCfg)) {
            System.out.println(" Fail.");
            return;
        }
        if (cardMgr.isbDebug())
            System.out.println(" Done.");
    }

    private void setNumber(ArrayList<CommandAPDU> cmds, byte[] num, byte ins, byte p1) {
        if (num.length <= 0xFF) {
            cmds.add(new CommandAPDU(RSA_SMPC_CLIENT, ins, p1, PART_0, num));
            return;
        }

        for (int i = num.length; i > 0; i -= 0xFF) {
            cmds.add(new CommandAPDU(RSA_SMPC_CLIENT, ins, p1, i / 0xFF > 0 ? PART_0 : PART_1,
                    Arrays.copyOfRange(num, i - 0xFF > 0 ? i - 0xFF : 0, i)));
        }
    }

    /**
     * Main entry point.
     *
     * @param args
     */
    public static void main(String[] args) {
        try {
            SimpleAPDU simpleAPDU = new SimpleAPDU();
            simpleAPDU.generateKeys();
            simpleAPDU.getKeys();
            simpleAPDU.signMessage();
            //simpleAPDU.test();
        } catch (Exception ex) {
            System.out.println("Exception : " + ex);
        }
    }

    public ResponseAPDU generateKeys() throws CardException {
        return cardMgr.transmit(APDU_GENERATE_KEYS);
    }

    public void getKeys() throws Exception {
        ResponseAPDU dServer = cardMgr.transmit(APDU_GET_D_SERVER);
        ResponseAPDU n = cardMgr.transmit(APDU_GET_N);

        try (OutputStream out = new FileOutputStream("for_server.key")) {
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(out));

            writer.write(String.format("%s%n%s%n", Util.toHex(Util.trimLeadingZeroes(dServer.getData())),
                    Util.toHex(Util.trimLeadingZeroes(n.getData()))));

            writer.flush();
        }
    }

    public ResponseAPDU signMessage() throws Exception {
        try (InputStream in = new FileInputStream("message.txt")) {
            BufferedReader reader = new BufferedReader(new InputStreamReader(in));

            byte[] num = Util.hexStringToByteArray(reader.readLine());
            // TODO, > comparison
            if (num.length > CLIENT_KEY_BYTE_LENGTH)
                throw new IllegalArgumentException("Message key cannot be larger than modulus.");

            setNumber(APDU_MESSAGE, num, SET_MESSAGE, NONE);

            if (reader.readLine() != null)
                throw new IOException("Wrong 'message.key' file format.");
        }

        for (CommandAPDU cmd : APDU_MESSAGE)
            cardMgr.transmit(cmd);

        ResponseAPDU response = cardMgr.transmit(APDU_SIGNATURE);

        try (OutputStream out = new FileOutputStream("client.sig")) {
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(out));
            try (InputStream in = new FileInputStream("message.txt")) {
                writer.write(new BufferedReader(new InputStreamReader(in)).readLine());
            }
            writer.write(String.format("%n%s%n", Util.toHex(Util.trimLeadingZeroes(response.getData()))));
            writer.flush();
        }

        return response;
    }

}
