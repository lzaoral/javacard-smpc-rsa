package tests;

import applet.RSAClient;
import cardTools.CardManager;
import cardTools.RunConfig;
import cardTools.Util;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
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

    private static final byte GENERATE_KEYS = 0x10;
    private static final byte GET_N = 0x11;
    private static final byte GET_D2 = 0x12;
    private static final byte UPDATE_KEYS = 0x20;
    private static final byte TEST = 0x30;
    private static final short CLIENT_KEY_BYTE_LENGTH = 256;


    private static String APPLET_AID = "482871d58ab7465e5e05";
    private static byte[] APPLET_AID_BYTE = Util.hexStringToByteArray(APPLET_AID);

    private static final int E = 65537;

    private static final CommandAPDU APDU_GENERATE_KEYS = new CommandAPDU(RSA_SMPC_CLIENT, GENERATE_KEYS,
            0x0, 0x0, BigInteger.valueOf(E).toByteArray());
    private static final CommandAPDU APDU_GET_N = new CommandAPDU(RSA_SMPC_CLIENT, GET_N,
            0x0, 0x0, CLIENT_KEY_BYTE_LENGTH);
    private static final CommandAPDU APDU_GET_D2 = new CommandAPDU(RSA_SMPC_CLIENT, GET_D2,
            0x0, 0x0, CLIENT_KEY_BYTE_LENGTH);
    private static final CommandAPDU APDU_TEST = new CommandAPDU(RSA_SMPC_CLIENT, TEST,
            0x0, 0x0, BigInteger.valueOf(E).toByteArray());


    /**
     * Main entry point.
     *
     * @param args
     */
    public static void main(String[] args) {
        try {
            generateKeys();
        } catch (Exception ex) {
            System.out.println("Exception : " + ex);
        }
    }

    public static ResponseAPDU generateKeys() throws Exception {
        final CardManager cardMngr = new CardManager(true, APPLET_AID_BYTE);
        final RunConfig runCfg = RunConfig.getDefaultConfig();

        // Running on physical card
        //runCfg.setTestCardType(RunConfig.CARD_TYPE.PHYSICAL);

        // Running in the simulator
        runCfg.setAppletToSimulate(RSAClient.class)
                .setTestCardType(RunConfig.CARD_TYPE.JCARDSIMLOCAL)
                .setbReuploadApplet(true)
                .setInstallData(new byte[8]);

        System.out.print("Connecting to card...");
        if (!cardMngr.Connect(runCfg)) {
            return null;
        }
        System.out.println(" Done.");

        ResponseAPDU response = sendCommandWithInitSequence(cardMngr, APDU_GENERATE_KEYS, null);
        response = sendCommandWithInitSequence(cardMngr, APDU_GET_N, null);
        response = sendCommandWithInitSequence(cardMngr, APDU_GET_D2, null);
        System.out.println(response);

        return response;
    }

    public static ResponseAPDU test() throws Exception {
        final CardManager cardMngr = new CardManager(true, APPLET_AID_BYTE);
        final RunConfig runCfg = RunConfig.getDefaultConfig();

        // Running on physical card
        //runCfg.setTestCardType(RunConfig.CARD_TYPE.PHYSICAL);

        // Running in the simulator
        runCfg.setAppletToSimulate(RSAClient.class)
                .setTestCardType(RunConfig.CARD_TYPE.JCARDSIMLOCAL)
                .setbReuploadApplet(true)
                .setInstallData(new byte[8]);

        System.out.print("Connecting to card...");
        if (!cardMngr.Connect(runCfg)) {
            return null;
        }
        System.out.println(" Done.");

        final ResponseAPDU response = sendCommandWithInitSequence(cardMngr, APDU_TEST, null);
        System.out.println(response);

        return response;
    }

    /**
     * Sending command to the card.
     * Enables to send init commands before the main one.
     *
     * @param cardMgr
     * @param command
     * @param initCommands
     * @return
     * @throws CardException
     */
    public static ResponseAPDU sendCommandWithInitSequence(CardManager cardMgr, CommandAPDU command,
                                                           ArrayList<CommandAPDU>  initCommands) throws CardException {
        if (initCommands != null) {
            for (CommandAPDU cmd : initCommands) {
                cardMgr.getChannel().transmit(cmd);
            }
        }

        return cardMgr.getChannel().transmit(command);
    }

}
