package tests.client_full;

import javacard.framework.ISO7816;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.io.*;

import org.junit.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static javacard.framework.ISO7816.*;
import static tests.client_full.ClientFullAPDU.*;

/**
 * Example test class for the applet
 * Note: If simulator cannot be started try adding "-noverify" JVM parameter
 *
 * @author xsvenda, Dusan Klinec (ph4r05), Lukas Zaoral
 */
public class ClientFullTest {

    private static final int TEST_COUNT = 0;
    private static final int SW_OK = 0x9000;

    private static boolean realCard = false;
    private ClientFullAPDU client;

    @BeforeClass
    public void setClass() throws Exception {
        client = new ClientFullAPDU(realCard);
    }

    @BeforeMethod
    public void setUp() throws Exception {
        client.transmit(new CommandAPDU(CLA_RSA_SMPC_CLIENT, INS_RESET, 0x00, 0x00));
        client.setDebug(true);
    }

    @Test
    public void wrongCLA() throws Exception {
        ResponseAPDU res = client.transmit(new CommandAPDU(
                0xFF, 0x00, 0x00, 0x00
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_CLA_NOT_SUPPORTED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void wrongINS() throws Exception {
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, 0xFF, 0x00, 0x00
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(ISO7816.SW_INS_NOT_SUPPORTED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void generateKeysWrongP1() throws Exception {
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_GENERATE_KEYS, 0x0F, 0x00
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void generateKeysWrongP2() throws Exception {
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_GENERATE_KEYS, 0x00, 0x0F
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void generateKeys() throws Exception {
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_GENERATE_KEYS, 0x00, 0x00
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void generateKeysTwice() throws Exception {
        generateKeys();

        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_GENERATE_KEYS, 0x00, 0x00
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void generateKeysAfterReset() throws Exception {
        generateKeys();

        ResponseAPDU responseAPDU = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_RESET, 0x00, 0x00
        ));
        Assert.assertEquals(0x9000, responseAPDU.getSW());
        Assert.assertEquals(0, responseAPDU.getData().length);

        generateKeys();
    }

    @Test
    public void resetCard() throws Exception {
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_RESET, 0x00, 0x00
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void resetWrongP1() throws Exception {
        generateKeys();

        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_RESET, 0xFF, 0x00
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_GENERATE_KEYS, 0x00, 0x00
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void resetWrongP2() throws Exception {
        generateKeys();

        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_RESET, 0x00, 0xFF
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_GENERATE_KEYS, 0x00, 0x00
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void getKeysWithoutGeneration() throws Exception {
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_GET_KEYS, 0x00, 0x00, CLIENT_ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_CONDITIONS_NOT_SATISFIED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void getKeysWrongP1() throws Exception {
        generateKeys();
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_GET_KEYS, 0xFF, 0x00, CLIENT_ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void getKeysWrongP2() throws Exception {
        generateKeys();
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_GET_KEYS, 0x00, 0xFF, CLIENT_ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void getN() throws Exception {
        generateKeys();
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_GET_KEYS, P1_GET_N, 0x00, CLIENT_ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(CLIENT_ARR_LENGTH, res.getData().length);
    }

    @Test
    public void getNTwice() throws Exception {
        generateKeys();
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_GET_KEYS, P1_GET_N, 0x00, CLIENT_ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(CLIENT_ARR_LENGTH, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_GET_KEYS, P1_GET_N, 0x00, CLIENT_ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void getD() throws Exception {
        generateKeys();
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_GET_KEYS, P1_GET_D1_SERVER, 0x00, CLIENT_ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(CLIENT_ARR_LENGTH, res.getData().length);
    }

    @Test
    public void getDTwice() throws Exception {
        generateKeys();
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_GET_KEYS, P1_GET_D1_SERVER, 0x00, CLIENT_ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(CLIENT_ARR_LENGTH, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_GET_KEYS, P1_GET_D1_SERVER, 0x00, CLIENT_ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void getKeys() throws Exception {
        generateKeys();
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_GET_KEYS, P1_GET_D1_SERVER, 0x00, CLIENT_ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(CLIENT_ARR_LENGTH, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_GET_KEYS, P1_GET_N, 0x00, CLIENT_ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(CLIENT_ARR_LENGTH, res.getData().length);
    }

    @Test
    public void getKeysSwitched() throws Exception {
        generateKeys();
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_GET_KEYS, P1_GET_N, 0x00, CLIENT_ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(CLIENT_ARR_LENGTH, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_GET_KEYS, P1_GET_D1_SERVER, 0x00, CLIENT_ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(CLIENT_ARR_LENGTH, res.getData().length);
    }

    @Test
    public void setMessageNoKeys() throws Exception {
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x00, P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_CONDITIONS_NOT_SATISFIED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void setMessageNoSentKeys() throws Exception {
        generateKeys();
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x00, P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_CONDITIONS_NOT_SATISFIED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void setMessageSentD() throws Exception {
        getD();
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x00, P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_CONDITIONS_NOT_SATISFIED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void setMessageSentN() throws Exception {
        getN();
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x00, P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_CONDITIONS_NOT_SATISFIED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void setSimpleMessage() throws Exception {
        getKeys();

        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x00, P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void setMultipartMessage() throws Exception {
        getKeys();

        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x00, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x00, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void setMultipartMessageTwice() throws Exception {
        getKeys();

        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x00, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x00, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x00, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x00, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void setMultipartMessageTwiceSwap() throws Exception {
        getKeys();

        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x00, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x00, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x00, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x00, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void resetMessage() throws Exception {
        getKeys();

        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x00, P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x00, P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void resetMultipartMessage() throws Exception {
        getKeys();

        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x00, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x00, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x00, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x00, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void setMultipartMessageSwap() throws Exception {
        getKeys();

        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x00, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x00, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void setMessageIncorrectP1() throws Exception {
        getKeys();
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x01, P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x00, P2_PART_1, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void signNoKey() throws Exception {
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SIGNATURE, 0x00, 0x00
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_CONDITIONS_NOT_SATISFIED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void signNoMessage() throws Exception {
        generateKeys();

        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SIGNATURE, 0x00, 0x00
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_CONDITIONS_NOT_SATISFIED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void signPartialMessage() throws Exception {
        getKeys();

        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x00, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SIGNATURE, 0x00, 0x00
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_CONDITIONS_NOT_SATISFIED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void signBadP1P2() throws Exception {
        setSimpleMessage();

        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SIGNATURE, 0xFF, 0x00
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SIGNATURE, 0x00, 0xFF
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void simpleSign() throws Exception {
        ResponseAPDU res = client.generateKeys();
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        client.getKeys();

        res = client.signMessage();
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(CLIENT_ARR_LENGTH, res.getData().length);
    }

    @Test
    public void signStressTest() throws Exception {
        ProcessBuilder serverGenerate = new ProcessBuilder("./../smpc_rsa", "server", "generate").directory(new File(TEST_PATH));
        ProcessBuilder serverSign = new ProcessBuilder("./../smpc_rsa", "server", "sign").directory(new File(TEST_PATH));
        ProcessBuilder serverVerify = new ProcessBuilder("./../smpc_rsa", "server", "verify").directory(new File(TEST_PATH));

        client.setDebug(false);

        int nokGenCount = 0;
        int nokSignCount = 0;

        for (int i = 1; i <= TEST_COUNT; i++) {
            System.out.printf("TEST %d: ", i);
            System.out.flush();

            resetCard();

            ResponseAPDU responseAPDU = client.generateKeys();
            Assert.assertEquals(SW_OK, responseAPDU.getSW());
            Assert.assertEquals(0, responseAPDU.getData().length);

            client.getKeys();

            responseAPDU = client.signMessage();
            Assert.assertNotNull(responseAPDU);
            Assert.assertEquals(SW_OK, responseAPDU.getSW());

            Process serverGenProc = serverGenerate.start();
            final BufferedReader errReader = new BufferedReader(
                    new InputStreamReader(new BufferedInputStream(serverGenProc.getErrorStream()))
            );

            OutputStreamWriter outputStreamWriter = new OutputStreamWriter(
                    new BufferedOutputStream(serverGenProc.getOutputStream())
            );
            outputStreamWriter.write("y\n");
            outputStreamWriter.flush();

            if (serverGenProc.waitFor() != 0) {
                String line;
                while ((line = errReader.readLine()) != null) {
                    System.out.println(line);
                }

                nokGenCount++;
                continue;
            }

            Process serverSignProc = serverSign.start();
            final BufferedReader errReader1 = new BufferedReader(
                    new InputStreamReader(new BufferedInputStream(serverSignProc.getErrorStream()))
            );

            if (serverSignProc.waitFor() != 0) {
                String line;
                while ((line = errReader1.readLine()) != null) {
                    System.out.println(line);
                }

                nokSignCount++;
                continue;
            }

            Assert.assertEquals(0, serverVerify.start().waitFor());
            System.out.println("\u001B[1;32mOK\u001B[0m");
        }

        System.out.printf("Result: Generate/Sign/All: %d/%d/%d (%.02f %% failed)",
                nokGenCount, nokSignCount, TEST_COUNT, (double) (nokGenCount + nokSignCount) * 100 / TEST_COUNT
        );
    }

}