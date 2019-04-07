package tests;

import applet.RSAClientSign;

import cardTools.CardManager;
import cardTools.RunConfig;
import cardTools.Util;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.util.ArrayList;

/**
 * Test class.
 * Note: If simulator cannot be started try adding "-noverify" JVM parameter
 *
 * @author Petr Svenda, Dusan Klinec (ph4r05)
 */
public class SimpleAPDU {
    private static final byte RSA_SMPC_CLIENT = 0x1C;

    private static final byte SET_KEYS = 0x10;
    private static final byte SET_E = 0x00; // TODO: may not be needed
    private static final byte SET_D = 0x01;
    private static final byte SET_N = 0x02;

    private static final byte SIGNATURE = 0x20;

    private static final byte TEST = 0x30;


    private static final byte CLIENT_KEY_BYTE_LENGTH = 0x30;


    private static String APPLET_AID = "482871d58ab7465e5e05";
    private static byte[] APPLET_AID_BYTE = Util.hexStringToByteArray(APPLET_AID);

    private static final int E = 65537;

    private static final CommandAPDU APDU_SET_E = new CommandAPDU(RSA_SMPC_CLIENT, SET_KEYS,
            SET_E, 0x0, BigInteger.valueOf(E).toByteArray());

    private final ArrayList<CommandAPDU> APDU_SET_N = new ArrayList<>();
    private final ArrayList<CommandAPDU> APDU_SET_D = new ArrayList<>();
    private final ArrayList<CommandAPDU> APDU_SIGNATURE = new ArrayList<>();

    private static final CommandAPDU APDU_TEST = new CommandAPDU(RSA_SMPC_CLIENT, TEST, 0x0, 0x0);


    public SimpleAPDU() throws IOException {
        try (InputStream in = new FileInputStream("client_card.key")) {
            BufferedReader reader = new BufferedReader(new InputStreamReader(in));

            String line = reader.readLine();
            int length = line.length() / 2;
            for (int i = 0; i < line.length(); i += length) {
                APDU_SET_D.add(new CommandAPDU(RSA_SMPC_CLIENT, SET_KEYS, SET_D, i / length == 0 ? 1 : 0,
                        new BigInteger(line.substring(i, i + length < line.length() ? i + length : line.length())).toByteArray()));
            }

            line = reader.readLine();
            length = line.length() / 2;
            for (int i = 0; i < line.length(); i += length) {
                APDU_SET_N.add(new CommandAPDU(RSA_SMPC_CLIENT, SET_KEYS, SET_N, i / length == 0 ? 1 : 0,
                        new BigInteger(line.substring(i, i + length < line.length() ? i + length : line.length())).toByteArray()));
            }

            if (reader.readLine() != null)
                throw new IOException("Wrong 'client_card.key' file format.");
        }

        // TODO: lol
        //APDU_SIGNATURE = new CommandAPDU(RSA_SMPC_CLIENT, SIGNATURE, 0x0, 0x0);
    }

    /**
     * Main entry point.
     *
     * @param args
     */
    public static void main(String[] args) {
        try {
            SimpleAPDU simpleAPDU = new SimpleAPDU();
            simpleAPDU.setKeys();
            simpleAPDU.test();

        } catch (Exception ex) {
            System.out.println("Exception : " + ex);
        }
    }

    public ResponseAPDU setKeys() throws Exception {
        final CardManager cardMgr = new CardManager(true, APPLET_AID_BYTE);
        final RunConfig runCfg = RunConfig.getDefaultConfig();

        // Running on physical card
        //runCfg.setTestCardType(RunConfig.CARD_TYPE.PHYSICAL);

        // Running in the simulator
        runCfg.setAppletToSimulate(RSAClientSign.class)
                .setTestCardType(RunConfig.CARD_TYPE.JCARDSIMLOCAL)
                .setbReuploadApplet(true)
                .setInstallData(new byte[8]);

        System.out.print("Connecting to card...");
        if (!cardMgr.Connect(runCfg)) {
            return null;
        }
        System.out.println(" Done.");

        ResponseAPDU response = cardMgr.getChannel().transmit(APDU_SET_E);
        System.out.println(response);

        for (CommandAPDU cmd : APDU_SET_D) {
            response = cardMgr.getChannel().transmit(cmd);
            System.out.println(response);
        }

        for (CommandAPDU cmd : APDU_SET_N) {
            response = cardMgr.getChannel().transmit(cmd);
            System.out.println(response);
        }

        return response;
    }

    public ResponseAPDU test() throws Exception {
        final CardManager cardMngr = new CardManager(true, APPLET_AID_BYTE);
        final RunConfig runCfg = RunConfig.getDefaultConfig();

        // Running on physical card
        //runCfg.setTestCardType(RunConfig.CARD_TYPE.PHYSICAL);

        // Running in the simulator
        runCfg.setAppletToSimulate(RSAClientSign.class)
                .setTestCardType(RunConfig.CARD_TYPE.JCARDSIMLOCAL)
                .setbReuploadApplet(true)
                .setInstallData(new byte[8]);

        System.out.print("Connecting to card...");
        if (!cardMngr.Connect(runCfg)) {
            return null;
        }
        System.out.println(" Done.");

        // TODO
        final ResponseAPDU response = cardMngr.getChannel().transmit(APDU_TEST);
        System.out.println(response);

        return response;
    }

}
