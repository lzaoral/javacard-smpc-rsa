package tests.client_sign;

import org.junit.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import java.io.*;
import java.util.Random;

import cardTools.Util;

import static javacard.framework.ISO7816.*;
import static tests.client_sign.ClientSignMgr.*;

/**
 * Test class for the Client-Sign applet.
 *
 * @author Lukas Zaoral
 */
public class ClientSignTest {

    private static final boolean REAL_CARD = false;
    private static final int TEST_COUNT = 50;
    private static final int SW_NO_ERROR = 0x9000; // overrides SW_NO_ERROR from ISO7816 to be a positive number
    private ClientSignMgr client;

    @BeforeClass(alwaysRun = true)
    public void setClass() throws Exception {
        client = new ClientSignMgr(REAL_CARD);
    }

    @BeforeMethod(alwaysRun = true)
    public void setUp() throws Exception {
        client.transmit(new CommandAPDU(CLA_RSA_SMPC_CLIENT_SIGN, INS_RESET, NONE, NONE));
        client.setDebug(true);
    }

    @Test(groups = "clientSignBasic")
    public void clientSignWrongCLA() throws Exception {
        ResponseAPDU res = client.transmit(new CommandAPDU(
                0xFF, NONE, NONE, NONE
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_CLA_NOT_SUPPORTED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientSignBasic")
    public void clientSignWrongINS() throws Exception {
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, 0xFF, NONE, NONE
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_INS_NOT_SUPPORTED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientSignBasic")
    public void clientSignResetCard() throws Exception {
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_RESET, NONE, NONE
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientSignBasic")
    public void clientSignResetWrongP1() throws Exception {
        clientSignSetKeys();

        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_RESET, 0xFF, NONE
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_KEYS, NONE, NONE
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientSignBasic")
    public void clientSignResetWrongP2() throws Exception {
        clientSignSetKeys();

        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_RESET, NONE, 0xFF
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_KEYS, NONE, NONE
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }


    @Test(groups = "clientSignSetKeys", dependsOnGroups = "clientSignBasic")
    public void clientSignSetKeysWrongP1() throws Exception {
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_KEYS, 0xFF, 0x02
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientSignSetKeys", dependsOnGroups = "clientSignBasic")
    public void clientSignSetKeysWrongP2Low() throws Exception {
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_KEYS, NONE, 0x0F
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }


    @Test(groups = "clientSignSetKeys", dependsOnGroups = "clientSignBasic")
    public void clientSignSetKeysWrongP2High() throws Exception {
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_KEYS, NONE, 0xF0
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientSignSetKeys", dependsOnGroups = "clientSignBasic")
    public void clientSignSetSingleD() throws Exception {
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_KEYS, P1_SET_D, P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientSignSetKeys", dependsOnGroups = "clientSignBasic")
    public void clientSignSetMultiD() throws Exception {
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_KEYS, P1_SET_D, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_KEYS, P1_SET_D, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientSignSetKeys", dependsOnGroups = "clientSignBasic")
    public void clientSignSetSingleN() throws Exception {
        clientSignSetSingleD();
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_KEYS, P1_SET_N, P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_WRONG_LENGTH, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientSignSetKeys", dependsOnGroups = "clientSignBasic")
    public void clientSignSetMultiN() throws Exception {
        clientSignSetSingleD();
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_KEYS, P1_SET_N, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_KEYS, P1_SET_N, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientSignSetKeys", dependsOnGroups = "clientSignBasic")
    public void clientSignSetWrongMultiN() throws Exception {
        clientSignSetSingleD();
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_KEYS, P1_SET_N, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_KEYS, P1_SET_N, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_WRONG_LENGTH, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientSignSetKeys", dependsOnGroups = "clientSignBasic")
    public void clientSignReclientSignSetSingleD() throws Exception {
        clientSignSetSingleD();
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_KEYS, P1_SET_D, P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientSignSetKeys", dependsOnGroups = "clientSignBasic")
    public void clientSignResetMultiD() throws Exception {
        clientSignSetMultiD();
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_KEYS, P1_SET_D, P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientSignSetKeys", dependsOnGroups = "clientSignBasic")
    public void clientSignSetNBeforeD() throws Exception {
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_KEYS, P1_SET_N, P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientSignSetKeys", dependsOnGroups = "clientSignBasic")
    public void clientSignResetSingleN() throws Exception {
        clientSignSetSingleN();

        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_KEYS, P1_SET_N, P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientSignSetKeys", dependsOnGroups = "clientSignBasic")
    public void clientSignResetMultiN() throws Exception {
        clientSignSetMultiN();
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_KEYS, P1_SET_N, P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientSignSetKeys", dependsOnGroups = "clientSignBasic")
    public void clientSignSetDMultiTwice() throws Exception {
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_KEYS, P1_SET_D, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_KEYS, P1_SET_D, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_KEYS, P1_SET_D, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_KEYS, P1_SET_D, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientSignSetKeys", dependsOnGroups = "clientSignBasic")
    public void clientSignSetDMultiSwitched() throws Exception {
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_KEYS, P1_SET_D, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_KEYS, P1_SET_D, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientSignSetKeys", dependsOnGroups = "clientSignBasic")
    public void clientSignSetNMultiSwitched() throws Exception {
        clientSignSetSingleD();
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_KEYS, P1_SET_N, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_KEYS, P1_SET_N, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientSignSetKeys", dependsOnGroups = "clientSignBasic")
    public void clientSignSetNMultiTwice() throws Exception {
        clientSignSetSingleD();

        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_KEYS, P1_SET_N, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_KEYS, P1_SET_N, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_KEYS, P1_SET_N, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_KEYS, P1_SET_N, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientSignSetKeys", dependsOnGroups = "clientSignBasic")
    public void clientSignSetNMultiTwiceSwap() throws Exception {
        clientSignSetSingleD();

        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_KEYS, P1_SET_N, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_KEYS, P1_SET_N, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_KEYS, P1_SET_N, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_KEYS, P1_SET_N, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientSignSetKeys", dependsOnGroups = "clientSignBasic")
    public void clientSignSetKeys() throws Exception {
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_KEYS, P1_SET_D, P2_PART_0, new byte[]{(byte) 0xF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_KEYS, P1_SET_N, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_KEYS, P1_SET_N, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientSignSetKeys", dependsOnGroups = "clientSignBasic")
    public void clientSignSetInitialisedKeys() throws Exception {
        clientSignSetKeys();

        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_KEYS, NONE, NONE
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientSignSetKeys", dependsOnGroups = "clientSignBasic")
    public void clientSignSetKeysAfterReset() throws Exception {
        clientSignSetKeys();

        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_RESET, NONE, NONE
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        clientSignSetKeys();
    }

    @Test(groups = "clientSignSetMessage", dependsOnGroups = "clientSignSetKeys")
    public void clientSignSetMessageNoKeys() throws Exception {
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_MESSAGE, NONE, P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_CONDITIONS_NOT_SATISFIED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientSignSetMessage", dependsOnGroups = "clientSignSetKeys")
    public void clientSignSetSimpleMessage() throws Exception {
        clientSignSetKeys();

        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_MESSAGE, NONE, P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientSignSetMessage", dependsOnGroups = "clientSignSetKeys")
    public void clientSignSetMultipartMessage() throws Exception {
        clientSignSetKeys();

        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_MESSAGE, NONE, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_MESSAGE, NONE, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientSignSetMessage", dependsOnGroups = "clientSignSetKeys")
    public void clientSignSetMultipartMessageTwice() throws Exception {
        clientSignSetKeys();

        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_MESSAGE, NONE, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_MESSAGE, NONE, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_MESSAGE, NONE, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_MESSAGE, NONE, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientSignSetMessage", dependsOnGroups = "clientSignSetKeys")
    public void clientSignSetMultipartMessageTwiceSwap() throws Exception {
        clientSignSetKeys();

        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_MESSAGE, NONE, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_MESSAGE, NONE, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_MESSAGE, NONE, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_MESSAGE, NONE, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientSignSetMessage", dependsOnGroups = "clientSignSetKeys")
    public void clientSignResetMessage() throws Exception {
        clientSignSetKeys();

        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_MESSAGE, NONE, P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_MESSAGE, NONE, P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientSignSetMessage", dependsOnGroups = "clientSignSetKeys")
    public void clientSignResetMultipartMessage() throws Exception {
        clientSignSetKeys();

        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_MESSAGE, NONE, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_MESSAGE, NONE, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_MESSAGE, NONE, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_MESSAGE, NONE, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientSignSetMessage", dependsOnGroups = "clientSignSetKeys")
    public void clientSignSetMultipartMessageSwap() throws Exception {
        clientSignSetKeys();

        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_MESSAGE, NONE, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_MESSAGE, NONE, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientSignSetMessage", dependsOnGroups = "clientSignSetKeys")
    public void clientSignSetMessageIncorrectP1() throws Exception {
        clientSignSetKeys();
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_MESSAGE, 0x01, P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_MESSAGE, NONE, P2_PART_1, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientSignSignature", dependsOnGroups = "clientSignSetMessage")
    public void clientSignSignNoKey() throws Exception {
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SIGNATURE, NONE, NONE
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_CONDITIONS_NOT_SATISFIED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientSignSignature", dependsOnGroups = "clientSignSetMessage")
    public void clientSignSignNoMessage() throws Exception {
        clientSignSetKeys();

        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SIGNATURE, NONE, NONE
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_CONDITIONS_NOT_SATISFIED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientSignSignature", dependsOnGroups = "clientSignSetMessage")
    public void clientSignSignPartialMessage() throws Exception {
        clientSignSetKeys();

        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_MESSAGE, NONE, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SIGNATURE, NONE, NONE
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_CONDITIONS_NOT_SATISFIED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientSignSignature", dependsOnGroups = "clientSignSetMessage")
    public void clientSignSignBadP1P2() throws Exception {
        clientSignSetSimpleMessage();

        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SIGNATURE, 0xFF, 0xFF
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SIGNATURE, NONE, 0xFF
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "clientSignSignature", dependsOnGroups = "clientSignSetMessage")
    public void clientSignSimpleSign() throws Exception {
        ResponseAPDU res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_KEYS, P1_SET_D, P2_DIVIDED | P2_PART_0,
                Util.hexStringToByteArray("96CECCABBD3CA81A2F23FA606AC4720D49B48A9C5D841CBE5E2A85C477A44310E8CAEABF238A42F26FE680AA01513D16776856AC23354C8D6312E756C055FB88C5B2C899F34E0F62B6813EC20E8DFE6778ADCE57C7EC0A4FBADD820451B29904F1E01275326D417486760A716B4921AE46C09138CFCA083270C1E45456E014EFB17F911DCE427023FC484189D3F92983B05CF849D05C77E4D9BF053A6618885DA544D0C583370F9F9FAFA962ABBCEDD2DBB81F3322469BC3607FB7B5B9C618E8959B95FE770E85B6D7BA864E8CF5423978AD936392D82BFE1A3970289924D06FEEE8DD9ABEF01B2D45314B9E5FBDADDD28ECAB282EEAB0A277DFB3CF948BFD")
        ));
        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_KEYS, P1_SET_D, P2_DIVIDED | P2_PART_1,
                Util.hexStringToByteArray("3B")
        ));
        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_KEYS, P1_SET_N, P2_DIVIDED | P2_PART_0,
                Util.hexStringToByteArray("5618288D09B6D1034168D4534AAD4B7DDB90AEEFF22C47A2BAF25C45AEBE28A34C39C1A8671DD74A302E794FAF0933BD13F56236D91DFA245B328A161B80FC7AEFFA8DDC242A529F1C756D0D437DD2977312A667E64EEA2FDA6660295FAFD67A758A534E76E1BF0B20E7F62A4E34994B398E4448F386CC008FA927582363864CE6577FA3932C79420F152A5C81671EA15977C74CC30D8412E8CF34F1EC5E23797D1394E2292F8E1DECCF7E8472DE96C83776BED2E979D6AD9F78FB0F91C02C604363007810B15C7FB665F1382FB478FF69A0BF008599EC62BBB107F3A8435C9A0994CA45C275C2B117682761EEABC1E6A9A00AAE8BE970FCA364745D5C849F")
        ));
        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_KEYS, P1_SET_N, P2_DIVIDED | P2_PART_1,
                Util.hexStringToByteArray("DA")
        ));
        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SET_MESSAGE, NONE, P2_PART_0,
                Util.hexStringToByteArray("f9822b96c3dcca942368507aeaad9c57267e6dab7ee42dfaf7dbbd2d499a75d623c65479217d89764923987fefd20ecc3eaf1247f09a7c3060091a4ca1251816f3e7c532894a42a1be3bdd0bbd1985f69e6784195cc7f9e45a9be6a4c80dc5db0ca7b08a")
        ));
        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = client.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT_SIGN, INS_SIGNATURE, NONE, NONE, ARR_LENGTH
        ));
        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(ARR_LENGTH, res.getData().length);
        Assert.assertArrayEquals(Util.hexStringToByteArray("01C86B7D2282ACDE771B705A2FEE6A6C621D942130A644CCFBA76D5A84ACCF2C6A98B20A023CDC85F1F1A50BF77C9B77FCC9DA206ED6F8FFFD69DE16C786DB19442FCB75B340C2527DEEF6046CAAED6020893C693CD9BA9FF88CD0E554F6185641F0CD47F406AFC79B59130E1DEC1F2D8E8E0D8F4CC94CFB9EF17156E43F4B2FF9D3666583AD2F8CBD8AEC9D16F546D0874B16DEB86892BE331313F5AC4463D28B73C2B0DCF3AD1937518C1D088AD36F7ED29F30542583FB0E67BC17330F519090733825B26730DA236BFDF11EE01F0FA38FE6F5EBD56AB4E37340552A829560DE32C7947E50B97C67649776DB3C18A26399DD2A985E711885A5D827EE3970B2"),
                res.getData());
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

    @Test(groups = "clientSignStressTest", dependsOnGroups = "clientSignSetMessage")
    public void clientSignStressTest() throws Exception {
        if (!new File(TEST_PATH + "smpc_rsa").isFile())
            Assert.fail("This test requires the reference 'smpc_rsa' in the tests (../) folder.");

        ProcessBuilder clientGenerate = new ProcessBuilder("./smpc_rsa", "client", "generate").directory(new File(TEST_PATH));
        ProcessBuilder serverGenerate = new ProcessBuilder("./smpc_rsa", "server", "generate").directory(new File(TEST_PATH));
        ProcessBuilder serverSign = new ProcessBuilder("./smpc_rsa", "server", "sign").directory(new File(TEST_PATH));
        ProcessBuilder serverVerify = new ProcessBuilder("./smpc_rsa", "server", "verify").directory(new File(TEST_PATH));

        client.setDebug(false);

        int nokGenCount = 0;
        int nokSignCount = 0;

        System.out.println("Running the sign client applet against reference implementation.");
        System.out.println("Each test may fail only when the modulus is unusable.");

        for (int i = 1; i <= TEST_COUNT; i++) {
            System.out.printf("TEST %d: ", i);
            System.out.flush();

            clientSignResetCard();

            generateMessage();

            Process clientGenProc = clientGenerate.start();
            final BufferedReader errReader = new BufferedReader(
                    new InputStreamReader(new BufferedInputStream(clientGenProc.getErrorStream()))
            );

            OutputStreamWriter outputStreamWriter = new OutputStreamWriter(
                    new BufferedOutputStream(clientGenProc.getOutputStream())
            );
            outputStreamWriter.write("y\n");
            outputStreamWriter.flush();

            if (clientGenProc.waitFor() != 0) {
                String line;
                while ((line = errReader.readLine()) != null) {
                    System.out.println(line);
                }

                Assert.fail("Client keys generation should never fail.");
            }

            client.setKeys();

            ResponseAPDU responseAPDU = client.signMessage();
            Assert.assertNotNull(responseAPDU);
            Assert.assertEquals(SW_NO_ERROR, responseAPDU.getSW());

            Process serverGenProc = serverGenerate.start();
            final BufferedReader errReader1 = new BufferedReader(
                    new InputStreamReader(new BufferedInputStream(serverGenProc.getErrorStream()))
            );

            OutputStreamWriter outputStreamWriter1 = new OutputStreamWriter(
                    new BufferedOutputStream(serverGenProc.getOutputStream())
            );
            outputStreamWriter1.write("y\n");
            outputStreamWriter1.flush();

            if (serverGenProc.waitFor() != 0) {
                String line;
                while ((line = errReader1.readLine()) != null) {
                    System.out.println(line);
                }

                nokGenCount++;
                continue;
            }

            Process serverSignProc = serverSign.start();
            final BufferedReader errReader2 = new BufferedReader(
                    new InputStreamReader(new BufferedInputStream(serverSignProc.getErrorStream()))
            );

            if (serverSignProc.waitFor() != 0) {
                String line;
                while ((line = errReader2.readLine()) != null) {
                    System.out.println(line);
                }

                Assert.fail("Final signature computation should never fail.");
            }

            Assert.assertEquals(0, serverVerify.start().waitFor());
            System.out.println("\u001B[1;32mOK\u001B[0m");
        }

        System.out.printf("Result: Fail Generate/Fail Sign/All: %d/%d/%d (%.02f %% failed)",
                nokGenCount, nokSignCount, TEST_COUNT, (double) (nokGenCount + nokSignCount) * 100 / TEST_COUNT
        );
    }

}
