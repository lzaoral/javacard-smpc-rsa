package tests;

import applet.RSAClientSign;

import cardTools.CardManager;
import cardTools.RunConfig;
import cardTools.Util;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.math.BigInteger;
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

    private static final byte SET_KEYS = 0x10;
    private static final byte SET_E = 0x00; // TODO: may not be needed
    private static final byte SET_D = 0x01;
    private static final byte SET_N = 0x02;

    private static final byte SET_MESSAGE = 0x11;

    private static final byte PART_0 = 0x00;
    private static final byte PART_1 = 0x01;

    private static final byte SIGNATURE = 0x20;

    private static final byte TEST = 0x30;


    private static final short CLIENT_KEY_BYTE_LENGTH = 256;


    private static String APPLET_AID = "482871d58ab7465e5e05";
    private static byte[] APPLET_AID_BYTE = Util.hexStringToByteArray(APPLET_AID);

    private static final int E = 65537;

    private static final CommandAPDU APDU_SET_E = new CommandAPDU(RSA_SMPC_CLIENT, SET_KEYS,
            SET_E, PART_0, BigInteger.valueOf(E).toByteArray());

    private final ArrayList<CommandAPDU> APDU_SET_N = new ArrayList<>();
    private final ArrayList<CommandAPDU> APDU_SET_D = new ArrayList<>();
    private final ArrayList<CommandAPDU> APDU_MESSAGE = new ArrayList<>();

    private static final CommandAPDU APDU_TEST = new CommandAPDU(RSA_SMPC_CLIENT, TEST, 0x0, 0x0);

    private static final CardManager cardMgr = new CardManager(true, APPLET_AID_BYTE);


    public SimpleAPDU() throws Exception {
        try (InputStream in = new FileInputStream("client_card.key")) {
            BufferedReader reader = new BufferedReader(new InputStreamReader(in));

            byte[] num = DatatypeConverter.parseHexBinary(reader.readLine());
            // TODO, > comparison
            if (num.length > CLIENT_KEY_BYTE_LENGTH)
                throw new IllegalArgumentException("Private key cannot be larger than modulus.");

            for (int i = num.length; i > 0; i -= 0xFF) {
                APDU_SET_D.add(new CommandAPDU(RSA_SMPC_CLIENT, SET_KEYS, SET_D, 1 - i / 0xFF,
                        Arrays.copyOfRange(num, i - 0xFF > 0 ? i - 0xFF : 0, i)));
            }

            num = DatatypeConverter.parseHexBinary(reader.readLine());
            if (num.length != CLIENT_KEY_BYTE_LENGTH)
                throw new IllegalArgumentException("Modulus is not a 256-bit number.");

            for (int i = num.length; i > 0; i -= 0xFF) {
                APDU_SET_N.add(new CommandAPDU(RSA_SMPC_CLIENT, SET_KEYS, SET_N, 1 - i / 0xFF,
                        Arrays.copyOfRange(num, i - 0xFF > 0 ? i - 0xFF : 0, i)));
            }

            if (reader.readLine() != null)
                throw new IOException("Wrong 'client_card.key' file format.");
        }

        try (InputStream in = new FileInputStream("message.txt")) {
            BufferedReader reader = new BufferedReader(new InputStreamReader(in));

            byte[] num = DatatypeConverter.parseHexBinary(reader.readLine());
            // TODO, > comparison
            if (num.length > CLIENT_KEY_BYTE_LENGTH)
                throw new IllegalArgumentException("Message key cannot be larger than modulus.");

            if (num.length <= 0xFF)
                APDU_MESSAGE.add(new CommandAPDU(RSA_SMPC_CLIENT, SET_MESSAGE, 0x0, PART_0, num));
            else {
                for (int i = num.length; i > 0; i -= 0xFF) {
                    APDU_MESSAGE.add(new CommandAPDU(RSA_SMPC_CLIENT, SET_MESSAGE, 0x0, 1 - i / 0xFF,
                            Arrays.copyOfRange(num, i - 0xFF > 0 ? i - 0xFF : 0, i)));
                }
            }

            if (reader.readLine() != null)
                throw new IOException("Wrong 'message.key' file format.");
        }

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
            System.out.println(" Fail.");
            return;
        }
        System.out.println(" Done.");
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
        cardMgr.getChannel().transmit(APDU_SET_E);
        for (CommandAPDU cmd : APDU_SET_D) {
            cardMgr.getChannel().transmit(cmd);
        }

        for (CommandAPDU cmd : APDU_SET_N) {
            cardMgr.getChannel().transmit(cmd);
        }

        for (CommandAPDU cmd : APDU_MESSAGE) {
            cardMgr.getChannel().transmit(cmd);
        }

        ResponseAPDU response = cardMgr.getChannel().transmit(new CommandAPDU(RSA_SMPC_CLIENT, SIGNATURE,
                0x0, 0x0, CLIENT_KEY_BYTE_LENGTH));

        try (OutputStream out = new FileOutputStream("client.sig")) {
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(out));
            try (InputStream in = new FileInputStream("message.txt")) {
                writer.write(new BufferedReader(new InputStreamReader(in)).readLine());
            }
            writer.write(System.lineSeparator());
            writer.write(DatatypeConverter.printHexBinary(response.getData()));
            writer.flush();
        }

        return response;
    }

    public ResponseAPDU test() throws Exception {
        // TODO
        final ResponseAPDU response = cardMgr.getChannel().transmit(APDU_TEST);
        System.out.println(response);

        return response;
    }

}
