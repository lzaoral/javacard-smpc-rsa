package tests.client_full;

import cardTools.Util;
import org.junit.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import java.io.*;
import java.util.Random;

import static javacard.framework.ISO7816.*;
import static tests.client_full.ClientFullMgr.*; // overrides SW_NO_ERROR from ISO7816 to be a positive number

/**
 * Test class for the Client-Full applet.
 *
 * @author Lukas Zaoral
 */
public class ClientFullTest {

    private static final boolean REAL_CARD = false;
    private static final int TEST_COUNT = 50;
    private static final int SW_NO_ERROR = 0x9000;
    private ClientFullMgr client;

    @BeforeClass(alwaysRun = true)
    public void setClass() throws Exception {
        client = new ClientFullMgr(REAL_CARD);
    }

    @BeforeMethod(alwaysRun = true)
    public void setUp() throws Exception {
        client.transmit(new CommandAPDU(CLA_RSA_SMPC_CLIENT, INS_RESET, NONE, NONE));
        client.setDebug(true);
    }

    @Test(groups = "clientFullBasic")
    public void clientFullWrongCLA() throws Exception {
        ResponseAPDU res = client.transmit(new CommandAPDU(
                0xFF, NONE, NONE, NONE
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_CLA_NOT_SUPPORTED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientFullBasic")
    public void clientFullWrongINS() throws Exception {
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, 0xFF, NONE, NONE
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_INS_NOT_SUPPORTED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientFullBasic")
    public void clientFullResetCard() throws Exception {
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_RESET, NONE, NONE
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientFullBasic")
    public void clientFullResetWrongP1() throws Exception {
        clientFullGenerateKeys();

        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_RESET, 0xFF, NONE
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_GENERATE_KEYS, NONE, NONE
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientFullBasic")
    public void clientFullResetWrongP2() throws Exception {
        clientFullGenerateKeys();

        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_RESET, NONE, 0xFF
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_GENERATE_KEYS, NONE, NONE
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientFullGenerate", dependsOnGroups = "clientFullBasic")
    public void clientFullGenerateKeysWrongP1() throws Exception {
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_GENERATE_KEYS, 0x0F, NONE
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientFullGenerate", dependsOnGroups = "clientFullBasic")
    public void clientFullGenerateKeysWrongP2() throws Exception {
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_GENERATE_KEYS, NONE, 0x0F
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientFullGenerate", dependsOnGroups = "clientFullBasic")
    public void clientFullGenerateKeys() throws Exception {
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_GENERATE_KEYS, NONE, NONE
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientFullGenerate", dependsOnGroups = "clientFullBasic")
    public void clientFullGenerateKeysTwice() throws Exception {
        clientFullGenerateKeys();

        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_GENERATE_KEYS, NONE, NONE
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientFullGenerate", dependsOnGroups = "clientFullBasic")
    public void clientFullGenerateKeysAfterReset() throws Exception {
        clientFullGenerateKeys();

        ResponseAPDU responseAPDU = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_RESET, NONE, NONE
        ));
        Assert.assertEquals(0x9000, responseAPDU.getSW());
        Assert.assertEquals(0, responseAPDU.getData().length);

        clientFullGenerateKeys();
    }

    @Test(groups = "clientFullGetKeys", dependsOnGroups = "clientFullGenerate")
    public void clientFullGetKeysWithoutGeneration() throws Exception {
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_GET_KEYS, NONE, NONE, ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_CONDITIONS_NOT_SATISFIED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientFullGetKeys", dependsOnGroups = "clientFullGenerate")
    public void clientFullGetKeysWrongP1() throws Exception {
        clientFullGenerateKeys();
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_GET_KEYS, 0xFF, NONE, ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientFullGetKeys", dependsOnGroups = "clientFullGenerate")
    public void clientFullGetKeysWrongP2() throws Exception {
        clientFullGenerateKeys();
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_GET_KEYS, NONE, 0xFF, ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientFullGetKeys", dependsOnGroups = "clientFullGenerate")
    public void clientFullGetN() throws Exception {
        clientFullGenerateKeys();
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_GET_KEYS, P1_GET_N, NONE, ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(ARR_LENGTH, res.getData().length);
    }

    @Test(groups = "clientFullGetKeys", dependsOnGroups = "clientFullGenerate")
    public void clientFullGetNTwice() throws Exception {
        clientFullGenerateKeys();
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_GET_KEYS, P1_GET_N, NONE, ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(ARR_LENGTH, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_GET_KEYS, P1_GET_N, NONE, ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientFullGetKeys", dependsOnGroups = "clientFullGenerate")
    public void clientFullGetD() throws Exception {
        clientFullGenerateKeys();
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_GET_KEYS, P1_GET_D1_SERVER, NONE, ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(ARR_LENGTH, res.getData().length);
    }

    @Test(groups = "clientFullGetKeys", dependsOnGroups = "clientFullGenerate")
    public void clientFullGetDTwice() throws Exception {
        clientFullGenerateKeys();
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_GET_KEYS, P1_GET_D1_SERVER, NONE, ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(ARR_LENGTH, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_GET_KEYS, P1_GET_D1_SERVER, NONE, ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientFullGetKeys", dependsOnGroups = "clientFullGenerate")
    public void clientFullGetKeys() throws Exception {
        clientFullGenerateKeys();
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_GET_KEYS, P1_GET_D1_SERVER, NONE, ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(ARR_LENGTH, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_GET_KEYS, P1_GET_N, NONE, ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(ARR_LENGTH, res.getData().length);
    }

    @Test(groups = "clientFullGetKeys", dependsOnGroups = "clientFullGenerate")
    public void clientFullGetKeysSwitched() throws Exception {
        clientFullGenerateKeys();
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_GET_KEYS, P1_GET_N, NONE, ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(ARR_LENGTH, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_GET_KEYS, P1_GET_D1_SERVER, NONE, ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(ARR_LENGTH, res.getData().length);
    }

    @Test(groups = "clientFullSetMessage", dependsOnGroups = "clientFullGetKeys")
    public void clientFullSetMessageNoKeys() throws Exception {
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, NONE, P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_CONDITIONS_NOT_SATISFIED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientFullSetMessage", dependsOnGroups = "clientFullGetKeys")
    public void clientFullSetMessageNoSentKeys() throws Exception {
        clientFullGenerateKeys();
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, NONE, P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_CONDITIONS_NOT_SATISFIED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientFullSetMessage", dependsOnGroups = "clientFullGetKeys")
    public void clientFullSetMessageSentD() throws Exception {
        clientFullGetD();
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, NONE, P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_CONDITIONS_NOT_SATISFIED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientFullSetMessage", dependsOnGroups = "clientFullGetKeys")
    public void clientFullSetMessageSentN() throws Exception {
        clientFullGetN();
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, NONE, P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_CONDITIONS_NOT_SATISFIED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientFullSetMessage", dependsOnGroups = "clientFullGetKeys")
    public void clientFullSetSimpleMessage() throws Exception {
        clientFullGetKeys();

        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, NONE, P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientFullSetMessage", dependsOnGroups = "clientFullGetKeys")
    public void clientFullSetMultipartMessage() throws Exception {
        clientFullGetKeys();

        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, NONE, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, NONE, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientFullSetMessage", dependsOnGroups = "clientFullGetKeys")
    public void clientFullSetMultipartMessageTwice() throws Exception {
        clientFullGetKeys();

        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, NONE, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, NONE, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, NONE, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, NONE, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientFullSetMessage", dependsOnGroups = "clientFullGetKeys")
    public void clientFullSetMultipartMessageTwiceSwap() throws Exception {
        clientFullGetKeys();

        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, NONE, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, NONE, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, NONE, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, NONE, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientFullSetMessage", dependsOnGroups = "clientFullGetKeys")
    public void clientFullResetMessage() throws Exception {
        clientFullGetKeys();

        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, NONE, P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, NONE, P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientFullSetMessage", dependsOnGroups = "clientFullGetKeys")
    public void clientFullResetMultipartMessage() throws Exception {
        clientFullGetKeys();

        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, NONE, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, NONE, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, NONE, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, NONE, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientFullSetMessage", dependsOnGroups = "clientFullGetKeys")
    public void clientFullSetMultipartMessageSwap() throws Exception {
        clientFullGetKeys();

        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, NONE, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, NONE, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientFullSetMessage", dependsOnGroups = "clientFullGetKeys")
    public void clientFullSetMessageIncorrectP1() throws Exception {
        clientFullGetKeys();
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x01, P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, NONE, P2_PART_1, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientFullSignature", dependsOnGroups = "clientFullSetMessage")
    public void clientFullSignNoKey() throws Exception {
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SIGNATURE, NONE, NONE
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_CONDITIONS_NOT_SATISFIED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientFullSignature", dependsOnGroups = "clientFullSetMessage")
    public void clientFullSignNoMessage() throws Exception {
        clientFullGenerateKeys();

        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SIGNATURE, NONE, NONE
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_CONDITIONS_NOT_SATISFIED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientFullSignature", dependsOnGroups = "clientFullSetMessage")
    public void clientFullSignPartialMessage() throws Exception {
        clientFullGetKeys();

        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, NONE, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SIGNATURE, NONE, NONE
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_CONDITIONS_NOT_SATISFIED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientFullSignature", dependsOnGroups = "clientFullSetMessage")
    public void clientFullSignBadP1P2() throws Exception {
        clientFullSetSimpleMessage();

        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SIGNATURE, 0xFF, NONE
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SIGNATURE, NONE, 0xFF
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientFullSignature", dependsOnGroups = "clientFullSetMessage")
    public void clientFullSimpleSign() throws Exception {
        generateMessage();

        ResponseAPDU res = client.generateKeys();
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        client.getKeys();

        res = client.signMessage();
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertNotEquals(0, res.getData().length); // can be 255-256 bytes long
    }

    @Test(groups = "clientFullSignature", dependsOnGroups = "clientFullSetMessage")
    public void clientFullMultiSign() throws Exception {
        generateMessage();

        ResponseAPDU res = client.generateKeys();
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        client.getKeys();

        res = client.signMessage();
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertNotEquals(0, res.getData().length);  // can be 255-256 bytes long

        res = client.signMessage();
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertNotEquals(0, res.getData().length);
    }

    private void generateMessage() throws Exception {
        try (OutputStream os = new FileOutputStream(MESSAGE_FILE_PATH)) {
            BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(os));

            byte[] bytes = new byte[ARR_LENGTH];
            new Random().nextBytes(bytes);
            bytes[0] &= 0x0F; // to avoid messages longer than modulus

            bw.write(Util.toHex(bytes));
            bw.flush();
        }
    }

    @Test(groups = "clientFullStressTest", dependsOnGroups = "clientFullSignature")
    public void clientFullStressTest() throws Exception {
        if (!new File(TEST_PATH + "smpc_rsa").isFile())
            Assert.fail("This test requires the reference 'smpc_rsa' in the tests (../) folder.");

        ProcessBuilder serverGenerate = new ProcessBuilder("./smpc_rsa", "server", "generate").directory(new File(TEST_PATH));
        ProcessBuilder serverSign = new ProcessBuilder("./smpc_rsa", "server", "sign").directory(new File(TEST_PATH));
        ProcessBuilder serverVerify = new ProcessBuilder("./smpc_rsa", "server", "verify").directory(new File(TEST_PATH));

        client.setDebug(false);

        int nokGenCount = 0;
        int nokSignCount = 0;

        System.out.println("Running the sign client applet against reference implementation.");
        System.out.println("Each test should fail only when the modulus is unusable.");
        System.out.println("Due to a bug in emulator, the test may very rarely fail with a wrong signature.");

        for (int i = 1; i <= TEST_COUNT; i++) {
            System.out.printf("TEST %d: ", i);
            System.out.flush();

            clientFullResetCard();
            generateMessage();

            ResponseAPDU responseAPDU = client.generateKeys();
            Assert.assertEquals(SW_NO_ERROR, responseAPDU.getSW());
            Assert.assertEquals(0, responseAPDU.getData().length);

            client.getKeys();

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

            responseAPDU = client.signMessage();
            Assert.assertNotNull(responseAPDU);
            Assert.assertEquals(SW_NO_ERROR, responseAPDU.getSW());

            Process serverSignProc = serverSign.start();
            final BufferedReader errReader1 = new BufferedReader(
                    new InputStreamReader(new BufferedInputStream(serverSignProc.getErrorStream()))
            );

            if (serverSignProc.waitFor() != 0) {
                String line;
                while ((line = errReader1.readLine()) != null) {
                    System.out.println(line);
                }

                if (REAL_CARD)
                    Assert.fail("Final signature computation on a real card should never fail.");

                nokSignCount++;
                continue;
            }

            Assert.assertEquals(0, serverVerify.start().waitFor());
            System.out.println("\u001B[1;32mOK\u001B[0m");
        }

        System.out.printf("Result: Fail Generate/Fail Sign/All: %d/%d/%d (%.02f %% failed)",
                nokGenCount, nokSignCount, TEST_COUNT, (double) (nokGenCount + nokSignCount) * 100 / TEST_COUNT
        );
    }

}
