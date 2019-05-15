package tests.client_full;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.junit.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.*;

import static javacard.framework.ISO7816.*;
import static tests.client_full.ClientFullAPDU.*;

/**
 * Test class for the Client-Full applet.
 *
 * @author Lukas Zaoral
 */
public class ClientFullTest {

    private static final boolean REAL_CARD = false;
    private static final int TEST_COUNT = 10;
    private static final int SW_OK = 0x9000;
    private ClientFullAPDU client;

    @BeforeClass
    public void setClass() throws Exception {
        client = new ClientFullAPDU(REAL_CARD);
    }

    @BeforeMethod
    public void setUp() throws Exception {
        client.transmit(new CommandAPDU(CLA_RSA_SMPC_CLIENT, INS_RESET, 0x00, 0x00));
        client.setDebug(true);
    }

    @Test
    public void clientFullWrongCLA() throws Exception {
        ResponseAPDU res = client.transmit(new CommandAPDU(
                0xFF, 0x00, 0x00, 0x00
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_CLA_NOT_SUPPORTED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void clientFullWrongINS() throws Exception {
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, 0xFF, 0x00, 0x00
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_INS_NOT_SUPPORTED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void clientFullGenerateKeysWrongP1() throws Exception {
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_GENERATE_KEYS, 0x0F, 0x00
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void clientFullGenerateKeysWrongP2() throws Exception {
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_GENERATE_KEYS, 0x00, 0x0F
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void clientFullGenerateKeys() throws Exception {
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_GENERATE_KEYS, 0x00, 0x00
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void clientFullGenerateKeysTwice() throws Exception {
        clientFullGenerateKeys();

        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_GENERATE_KEYS, 0x00, 0x00
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void clientFullGenerateKeysAfterReset() throws Exception {
        clientFullGenerateKeys();

        ResponseAPDU responseAPDU = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_RESET, 0x00, 0x00
        ));
        Assert.assertEquals(0x9000, responseAPDU.getSW());
        Assert.assertEquals(0, responseAPDU.getData().length);

        clientFullGenerateKeys();
    }

    @Test
    public void clientFullResetCard() throws Exception {
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_RESET, 0x00, 0x00
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void clientFullResetWrongP1() throws Exception {
        clientFullGenerateKeys();

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
    public void clientFullResetWrongP2() throws Exception {
        clientFullGenerateKeys();

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
    public void clientFullGetKeysWithoutGeneration() throws Exception {
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_GET_KEYS, 0x00, 0x00, CLIENT_ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_CONDITIONS_NOT_SATISFIED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void clientFullGetKeysWrongP1() throws Exception {
        clientFullGenerateKeys();
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_GET_KEYS, 0xFF, 0x00, CLIENT_ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void clientFullGetKeysWrongP2() throws Exception {
        clientFullGenerateKeys();
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_GET_KEYS, 0x00, 0xFF, CLIENT_ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void clientFullGetN() throws Exception {
        clientFullGenerateKeys();
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_GET_KEYS, P1_GET_N, 0x00, CLIENT_ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(CLIENT_ARR_LENGTH, res.getData().length);
    }

    @Test
    public void clientFullGetNTwice() throws Exception {
        clientFullGenerateKeys();
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
    public void clientFullGetD() throws Exception {
        clientFullGenerateKeys();
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_GET_KEYS, P1_GET_D1_SERVER, 0x00, CLIENT_ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(CLIENT_ARR_LENGTH, res.getData().length);
    }

    @Test
    public void clientFullGetDTwice() throws Exception {
        clientFullGenerateKeys();
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
    public void clientFullGetKeys() throws Exception {
        clientFullGenerateKeys();
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
    public void clientFullGetKeysSwitched() throws Exception {
        clientFullGenerateKeys();
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
    public void clientFullSetMessageNoKeys() throws Exception {
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x00, P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_CONDITIONS_NOT_SATISFIED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void clientFullSetMessageNoSentKeys() throws Exception {
        clientFullGenerateKeys();
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x00, P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_CONDITIONS_NOT_SATISFIED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void clientFullSetMessageSentD() throws Exception {
        clientFullGetD();
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x00, P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_CONDITIONS_NOT_SATISFIED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void clientFullSetMessageSentN() throws Exception {
        clientFullGetN();
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x00, P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_CONDITIONS_NOT_SATISFIED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void clientFullSetSimpleMessage() throws Exception {
        clientFullGetKeys();

        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x00, P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void clientFullSetMultipartMessage() throws Exception {
        clientFullGetKeys();

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
    public void clientFullSetMultipartMessageTwice() throws Exception {
        clientFullGetKeys();

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
    public void clientFullSetMultipartMessageTwiceSwap() throws Exception {
        clientFullGetKeys();

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
    public void clientFullResetMessage() throws Exception {
        clientFullGetKeys();

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
    public void clientFullResetMultipartMessage() throws Exception {
        clientFullGetKeys();

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
    public void clientFullSetMultipartMessageSwap() throws Exception {
        clientFullGetKeys();

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
    public void clientFullSetMessageIncorrectP1() throws Exception {
        clientFullGetKeys();
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
    public void clientFullSignNoKey() throws Exception {
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SIGNATURE, 0x00, 0x00
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_CONDITIONS_NOT_SATISFIED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void clientFullSignNoMessage() throws Exception {
        clientFullGenerateKeys();

        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SIGNATURE, 0x00, 0x00
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_CONDITIONS_NOT_SATISFIED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void clientFullSignPartialMessage() throws Exception {
        clientFullGetKeys();

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
    public void clientFullSignBadP1P2() throws Exception {
        clientFullSetSimpleMessage();

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
    public void clientFullSimpleSign() throws Exception {
        ResponseAPDU res = client.generateKeys();
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        client.getKeys();

        res = client.signMessage();
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(CLIENT_ARR_LENGTH, res.getData().length);
    }

    @Test
    public void clientFullMultiSign() throws Exception {
        ResponseAPDU res = client.generateKeys();
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        client.getKeys();

        res = client.signMessage();
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(CLIENT_ARR_LENGTH, res.getData().length);

        res = client.signMessage();
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(CLIENT_ARR_LENGTH, res.getData().length);
    }

    @Test
    public void clientFullStressTest() throws Exception {
        System.out.println("This test requires the reference 'smpc_rsa' in the tests (../) folder.");

        ProcessBuilder serverGenerate = new ProcessBuilder("./../smpc_rsa", "server", "generate").directory(new File(TEST_PATH));
        ProcessBuilder serverSign = new ProcessBuilder("./../smpc_rsa", "server", "sign").directory(new File(TEST_PATH));
        ProcessBuilder serverVerify = new ProcessBuilder("./../smpc_rsa", "server", "verify").directory(new File(TEST_PATH));

        client.setDebug(false);

        int nokGenCount = 0;
        int nokSignCount = 0;

        System.out.println("Runs the applet against reference implementation.");
        System.out.println("Each test may fail only when the modulus is unusable.");
        System.out.println("Due to a bug in emulator, the test may very rarely fail with a wrong signature.");

        for (int i = 1; i <= TEST_COUNT; i++) {
            System.out.printf("TEST %d: ", i);
            System.out.flush();

            clientFullResetCard();

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
