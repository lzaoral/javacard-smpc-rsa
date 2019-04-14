package tests;

import applet.RSAClientSign;

import cardTools.CardManager;
import cardTools.RunConfig;
import cardTools.Util;

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

    private static final byte SET_KEYS = 0x10;
    private static final byte SET_D = 0x00;
    private static final byte SET_N = 0x01;

    private static final byte SET_MESSAGE = 0x11;

    private static final byte PART_0 = 0x00;
    private static final byte PART_1 = 0x01;

    private static final byte SIGNATURE = 0x20;

    private static final byte TEST = 0x30;


    private static final short CLIENT_KEY_BYTE_LENGTH = 256;

    private static final boolean realCard = true;

    private static String APPLET_AID = "0102030405060708090102";
    private static byte[] APPLET_AID_BYTE = Util.hexStringToByteArray(APPLET_AID);

    private static final ArrayList<CommandAPDU> APDU_SET_N = new ArrayList<>();
    private static final ArrayList<CommandAPDU> APDU_SET_D = new ArrayList<>();
    private static final ArrayList<CommandAPDU> APDU_MESSAGE = new ArrayList<>();

    private static final CommandAPDU APDU_TEST = new CommandAPDU(RSA_SMPC_CLIENT, TEST, NONE, NONE);

    private static final CardManager cardMgr = new CardManager(APPLET_AID_BYTE);

    public SimpleAPDU() throws Exception {
        try (InputStream in = new FileInputStream("client_card.key")) {
            BufferedReader reader = new BufferedReader(new InputStreamReader(in));

            byte[] num = Util.hexStringToByteArray(reader.readLine());
            // TODO, > comparison
            if (num.length > CLIENT_KEY_BYTE_LENGTH)
                throw new IllegalArgumentException("Private key cannot be larger than modulus.");

            setNumber(APDU_SET_D, num, SET_KEYS, SET_D);

            num = Util.hexStringToByteArray(reader.readLine());
            if (num.length != CLIENT_KEY_BYTE_LENGTH)
                throw new IllegalArgumentException("Modulus is not a 256-bit number.");

            setNumber(APDU_SET_N, num, SET_KEYS, SET_N);

            if (reader.readLine() != null)
                throw new IOException("Wrong 'client_card.key' file format.");
        }

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

        final RunConfig runCfg = RunConfig.getDefaultConfig();

        if (realCard)
            runCfg.setTestCardType(RunConfig.CARD_TYPE.PHYSICAL);
        else {
            runCfg.setAppletToSimulate(RSAClientSign.class)
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
            simpleAPDU.setKeys();
            //simpleAPDU.test();
        } catch (Exception ex) {
            System.out.println("Exception : " + ex);
        }
    }

    public void setKeys() throws Exception {
        for (CommandAPDU cmd : APDU_SET_D)
            cardMgr.transmit(cmd);

        for (CommandAPDU cmd : APDU_SET_N)
            cardMgr.transmit(cmd);

        for (CommandAPDU cmd : APDU_MESSAGE)
            cardMgr.transmit(cmd);
    }

    public ResponseAPDU signMessage() throws Exception {
        ResponseAPDU response = cardMgr.transmit(new CommandAPDU(RSA_SMPC_CLIENT, SIGNATURE, NONE, NONE,
                CLIENT_KEY_BYTE_LENGTH));

        try (OutputStream out = new FileOutputStream("client.sig")) {
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(out));
            try (InputStream in = new FileInputStream("message.txt")) {
                writer.write(new BufferedReader(new InputStreamReader(in)).readLine());
            }
            writer.write(String.format("%s%s%s", System.lineSeparator(),
                    Util.toHex(Util.trimLeadingZeroes(response.getData())), System.lineSeparator()));
            writer.flush();
        }

        return response;
    }

    public ResponseAPDU test() throws Exception {
        return cardMgr.transmit(APDU_TEST);
    }

}
