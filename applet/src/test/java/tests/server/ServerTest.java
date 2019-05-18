package tests.server;

import cardTools.Util;

import org.junit.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.OutputStreamWriter;

import static javacard.framework.ISO7816.*;
import static tests.server.ServerAPDU.*;

/**
 * Test class for the Server applet.
 *
 * @author Lukas Zaoral
 */
public class ServerTest {

    private static final boolean REAL_CARD = false;
    private static final int TEST_COUNT = 1000;
    private static final int SW_NO_ERROR = 0x9000;
    private ServerAPDU server;

    @BeforeClass(alwaysRun = true)
    public void setClass() throws Exception {
        server = new ServerAPDU(REAL_CARD);
    }

    @BeforeMethod(alwaysRun = true)
    public void setUp() throws Exception {
        server.transmit(new CommandAPDU(CLA_RSA_SMPC_SERVER, INS_RESET, NONE, NONE));
        server.setDebug(true);
    }

    @Test(groups = "serverBasic")
    public void serverWrongCLA() throws Exception {
        ResponseAPDU res = server.transmit(new CommandAPDU(
                0xFF, NONE, NONE, NONE
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_CLA_NOT_SUPPORTED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverBasic")
    public void serverWrongINS() throws Exception {
        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, 0xFF, NONE, NONE
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_INS_NOT_SUPPORTED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverBasic")
    public void serverResetCard() throws Exception {
        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_RESET, NONE, NONE
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverBasic")
    public void serverResetWrongP1() throws Exception {
        serverGenerateKeys();

        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_RESET, 0xFF, NONE
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_GENERATE_KEYS, NONE, NONE
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverBasic")
    public void serverResetWrongP2() throws Exception {
        serverGenerateKeys();

        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_RESET, NONE, 0xFF
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_GENERATE_KEYS, NONE, NONE
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverGenerate", dependsOnGroups = "serverBasic")
    public void serverGenerateKeysWrongP1() throws Exception {
        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_GENERATE_KEYS, 0x0F, NONE
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverGenerate", dependsOnGroups = "serverBasic")
    public void serverGenerateKeysWrongP2() throws Exception {
        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_GENERATE_KEYS, NONE, 0x0F
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverGenerate", dependsOnGroups = "serverBasic")
    public void serverGenerateKeys() throws Exception {
        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_GENERATE_KEYS, NONE, NONE
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverGenerate", dependsOnGroups = "serverBasic")
    public void serverGenerateKeysTwice() throws Exception {
        serverGenerateKeys();

        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_GENERATE_KEYS, NONE, NONE
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverGenerate", dependsOnGroups = "serverBasic")
    public void serverGenerateKeysAfterReset() throws Exception {
        serverGenerateKeys();
        serverResetCard();
        serverGenerateKeys();
    }

    @Test(groups = "serverSetClientKeys", dependsOnGroups = "serverGenerate")
    public void serverSetKeysWrongP1() throws Exception {
        serverGenerateKeys();

        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_KEYS, 0xFF, 0x02
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverSetClientKeys", dependsOnGroups = "serverGenerate")
    public void serverSetKeysWrongP2Low() throws Exception {
        serverGenerateKeys();

        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_KEYS, NONE, 0x0F
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverSetClientKeys", dependsOnGroups = "serverGenerate")
    public void serverSetKeysWrongP2High() throws Exception {
        serverGenerateKeys();

        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_KEYS, NONE, 0xF0
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverSetClientKeys", dependsOnGroups = "serverGenerate")
    public void serverSetKeysNoGeneration() throws Exception {
        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_KEYS, P1_SET_D1_SERVER, P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_CONDITIONS_NOT_SATISFIED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverSetClientKeys", dependsOnGroups = "serverGenerate")
    public void serverSetSingleD() throws Exception {
        serverGenerateKeys();

        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_KEYS, P1_SET_D1_SERVER, P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverSetClientKeys", dependsOnGroups = "serverGenerate")
    public void serverSetMultiD() throws Exception {
        serverGenerateKeys();

        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_KEYS, P1_SET_D1_SERVER, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_KEYS, P1_SET_D1_SERVER, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverSetClientKeys", dependsOnGroups = "serverGenerate")
    public void serverSetSingleN() throws Exception {
        serverSetSingleD();
        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_KEYS, P1_SET_N1, P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_WRONG_LENGTH, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverSetClientKeys", dependsOnGroups = "serverGenerate")
    public void serverSetMultiN() throws Exception {
        serverSetSingleD();
        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_KEYS, P1_SET_N1, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_KEYS, P1_SET_N1, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverSetClientKeys", dependsOnGroups = "serverGenerate")
    public void serverSetWrongMultiN() throws Exception {
        serverSetSingleD();
        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_KEYS, P1_SET_N1, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_KEYS, P1_SET_N1, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_WRONG_LENGTH, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverSetClientKeys", dependsOnGroups = "serverGenerate")
    public void serverResetSingleD() throws Exception {
        serverSetSingleD();
        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_KEYS, P1_SET_D1_SERVER, P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverSetClientKeys", dependsOnGroups = "serverGenerate")
    public void serverResetMultiD() throws Exception {
        serverSetMultiD();
        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_KEYS, P1_SET_D1_SERVER, P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverSetClientKeys", dependsOnGroups = "serverGenerate")
    public void serverSetNBeforeD() throws Exception {
        serverGenerateKeys();

        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_KEYS, P1_SET_N1, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_KEYS, P1_SET_N1, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_KEYS, P1_SET_D1_SERVER, P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverSetClientKeys", dependsOnGroups = "serverGenerate")
    public void serverResetSingleN() throws Exception {
        serverSetSingleN();

        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_KEYS, P1_SET_N1, P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverSetClientKeys", dependsOnGroups = "serverGenerate")
    public void serverResetMultiN() throws Exception {
        serverSetMultiN();
        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_KEYS, P1_SET_N1, P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverSetClientKeys", dependsOnGroups = "serverGenerate")
    public void serverSetDMultiTwice() throws Exception {
        serverGenerateKeys();

        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_KEYS, P1_SET_D1_SERVER, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_KEYS, P1_SET_D1_SERVER, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_KEYS, P1_SET_D1_SERVER, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_KEYS, P1_SET_D1_SERVER, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverSetClientKeys", dependsOnGroups = "serverGenerate")
    public void serverKeysSetDMultiSwitched() throws Exception {
        serverGenerateKeys();

        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_KEYS, P1_SET_D1_SERVER, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_KEYS, P1_SET_D1_SERVER, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverSetClientKeys", dependsOnGroups = "serverGenerate")
    public void serverSetKeysNMultiSwitched() throws Exception {
        serverSetSingleD();
        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_KEYS, P1_SET_N1, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_KEYS, P1_SET_N1, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverSetClientKeys", dependsOnGroups = "serverGenerate")
    public void serverSetKeysNMultiTwice() throws Exception {
        serverSetSingleD();

        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_KEYS, P1_SET_N1, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_KEYS, P1_SET_N1, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_KEYS, P1_SET_N1, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_KEYS, P1_SET_N1, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverSetClientKeys", dependsOnGroups = "serverGenerate")
    public void serverSetKeysNMultiTwiceSwap() throws Exception {
        serverSetSingleD();

        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_KEYS, P1_SET_N1, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_KEYS, P1_SET_N1, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_KEYS, P1_SET_N1, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_KEYS, P1_SET_N1, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverSetClientKeys", dependsOnGroups = "serverGenerate")
    public void serverSetKeys() throws Exception {
        serverGenerateKeys();

        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_KEYS, P1_SET_D1_SERVER, P2_PART_0, new byte[]{(byte) 0xF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_KEYS, P1_SET_N1, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_KEYS, P1_SET_N1, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverSetClientKeys", dependsOnGroups = "serverGenerate")
    public void serverSetKeysTwice() throws Exception {
        serverSetKeys();

        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_KEYS, NONE, NONE
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverSetClientKeys", dependsOnGroups = "serverGenerate")
    public void serverSetKeysAfterReset() throws Exception {
        serverSetKeys();

        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_RESET, NONE, NONE
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        serverSetKeys();
    }

    @Test(groups = "serverGetModulus", dependsOnGroups = "serverSetClientKeys")
    public void serverGetModulusWithoutClientShare() throws Exception {
        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_GET_PUBLIC_MODULUS, NONE, NONE, CLIENT_ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_CONDITIONS_NOT_SATISFIED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverGetModulus", dependsOnGroups = "serverSetClientKeys")
    public void serverGetModulusWrongP1() throws Exception {
        serverSetKeys();
        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_GET_PUBLIC_MODULUS, 0xFF, NONE, CLIENT_ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverGetModulus", dependsOnGroups = "serverSetClientKeys")
    public void serverGetModulusWrongP2() throws Exception {
        serverSetKeys();
        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_GET_PUBLIC_MODULUS, NONE, 0xFF, CLIENT_ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverGetModulus", dependsOnGroups = "serverSetClientKeys")
    public void serverGetModulus() throws Exception {
        ResponseAPDU res;

        do {
            serverResetCard();
            serverSetKeys();

            res = server.transmit(new CommandAPDU(
                    CLA_RSA_SMPC_SERVER, INS_GET_PUBLIC_MODULUS, NONE, P2_PART_0, CLIENT_ARR_LENGTH
            ));
            Assert.assertNotNull(res);

        } while (res.getSW() == SW_WRONG_LENGTH);

        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(CLIENT_ARR_LENGTH, res.getData().length);

        res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_GET_PUBLIC_MODULUS, NONE, P2_PART_1, CLIENT_ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(CLIENT_ARR_LENGTH, res.getData().length);
    }

    @Test(groups = "serverGetModulus", dependsOnGroups = "serverSetClientKeys")
    public void serverGetModulusPart1Twice() throws Exception {
        serverGetModulus();
        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_GET_PUBLIC_MODULUS, NONE, P2_PART_0, CLIENT_ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(CLIENT_ARR_LENGTH, res.getData().length);

        res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_GET_PUBLIC_MODULUS, NONE, P2_PART_0, CLIENT_ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(CLIENT_ARR_LENGTH, res.getData().length);
    }

    @Test(groups = "serverGetModulus", dependsOnGroups = "serverSetClientKeys")
    public void serverGetModulusPart2Twice() throws Exception {
        serverGetModulus();
        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_GET_PUBLIC_MODULUS, NONE, P2_PART_1, CLIENT_ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(CLIENT_ARR_LENGTH, res.getData().length);

        res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_GET_PUBLIC_MODULUS, NONE, P2_PART_1, CLIENT_ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(CLIENT_ARR_LENGTH, res.getData().length);
    }

    @Test(groups = "serverGetModulus", dependsOnGroups = "serverSetClientKeys")
    public void serverGetModulusSwap() throws Exception {
        serverGetModulus();
        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_GET_PUBLIC_MODULUS, NONE, P2_PART_1, CLIENT_ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(CLIENT_ARR_LENGTH, res.getData().length);

        res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_GET_PUBLIC_MODULUS, NONE, P2_PART_0, CLIENT_ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(CLIENT_ARR_LENGTH, res.getData().length);
    }

    @Test(groups = "serverGetModulus", dependsOnGroups = "serverSetClientKeys")
    public void serverGetModulusTwice() throws Exception {
        serverGetModulus();

        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_GET_PUBLIC_MODULUS, NONE, P2_PART_0, CLIENT_ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(CLIENT_ARR_LENGTH, res.getData().length);

        res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_GET_PUBLIC_MODULUS, NONE, P2_PART_1, CLIENT_ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(CLIENT_ARR_LENGTH, res.getData().length);
    }

    @Test(groups = "serverSetClientSignature", dependsOnGroups = "serverGetModulus")
    public void serverSetClientSignatureWrongP1() throws Exception {
        serverGetModulus();

        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_SIGNATURE, 0xFF, 0x02
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverSetClientSignature", dependsOnGroups = "serverGetModulus")
    public void serverSetClientSignatureWrongP2Low() throws Exception {
        serverGetModulus();

        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_SIGNATURE, NONE, 0x0F
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }


    @Test(groups = "serverSetClientSignature", dependsOnGroups = "serverGetModulus")
    public void serverSetClientSignatureWrongP2High() throws Exception {
        serverGetModulus();

        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_SIGNATURE, NONE, 0xF0
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverSetClientSignature", dependsOnGroups = "serverGetModulus")
    public void serverSetClientSignatureNoModulus() throws Exception {
        serverGenerateKeys();

        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_SIGNATURE, P1_SET_MESSAGE, P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_CONDITIONS_NOT_SATISFIED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverSetClientSignature", dependsOnGroups = "serverGetModulus")
    public void serverSetClientSignatureSingleMsg() throws Exception {
        serverGetModulus();

        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_SIGNATURE, P1_SET_MESSAGE, P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverSetClientSignature", dependsOnGroups = "serverGetModulus")
    public void serverSetClientSignatureMultiMsg() throws Exception {
        serverGetModulus();

        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_SIGNATURE, P1_SET_MESSAGE, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_SIGNATURE, P1_SET_MESSAGE, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverSetClientSignature", dependsOnGroups = "serverGetModulus")
    public void serverSetClientSignatureSingleSig() throws Exception {
        serverSetClientSignatureSingleMsg();
        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_SIGNATURE, P1_SET_SIGNATURE, P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverSetClientSignature", dependsOnGroups = "serverGetModulus")
    public void serverSetClientSignatureMultiSig() throws Exception {
        serverSetClientSignatureSingleMsg();
        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_SIGNATURE, P1_SET_SIGNATURE, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_SIGNATURE, P1_SET_SIGNATURE, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverSetClientSignature", dependsOnGroups = "serverGetModulus")
    public void serverSetClientSignatureSignatureMsgTwice() throws Exception {
        serverSetClientSignatureSingleMsg();
        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_SIGNATURE, P1_SET_MESSAGE, P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverSetClientSignature", dependsOnGroups = "serverGetModulus")
    public void serverSetClientSignatureSignatureMultiMsgTwice() throws Exception {
        serverSetClientSignatureMultiMsg();
        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_SIGNATURE, P1_SET_MESSAGE, P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverSetClientSignature", dependsOnGroups = "serverGetModulus")
    public void serverSetClientSignatureSigBeforeMsg() throws Exception {
        serverGetModulus();

        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_SIGNATURE, P1_SET_SIGNATURE, P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverSetClientSignature", dependsOnGroups = "serverGetModulus")
    public void serverSetClientSignatureResetSingleSig() throws Exception {
        serverSetClientSignatureSingleSig();

        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_SIGNATURE, P1_SET_SIGNATURE, P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverSetClientSignature", dependsOnGroups = "serverGetModulus")
    public void serverSetClientSignatureResetMultiSig() throws Exception {
        serverSetClientSignatureSingleSig();
        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_SIGNATURE, P1_SET_SIGNATURE, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_SIGNATURE, P1_SET_SIGNATURE, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverSetClientSignature", dependsOnGroups = "serverGetModulus")
    public void serverSetClientSignatureMultiMsgTwice() throws Exception {
        serverGetModulus();

        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_SIGNATURE, P1_SET_MESSAGE, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_SIGNATURE, P1_SET_MESSAGE, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_SIGNATURE, P1_SET_MESSAGE, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_SIGNATURE, P1_SET_MESSAGE, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverSetClientSignature", dependsOnGroups = "serverGetModulus")
    public void serverSetClientSignatureMultiMsgSwitched() throws Exception {
        serverGetModulus();

        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_SIGNATURE, P1_SET_MESSAGE, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_SIGNATURE, P1_SET_MESSAGE, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverSetClientSignature", dependsOnGroups = "serverGetModulus")
    public void serverSetClientSignatureMultiSigSwitched() throws Exception {
        serverGetModulus();

        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_SIGNATURE, P1_SET_SIGNATURE, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_SIGNATURE, P1_SET_SIGNATURE, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverSetClientSignature", dependsOnGroups = "serverGetModulus")
    public void serverSetClientSignatureMultiSigTwice() throws Exception {
        serverGetModulus();

        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_SIGNATURE, P1_SET_SIGNATURE, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_SIGNATURE, P1_SET_SIGNATURE, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_SIGNATURE, P1_SET_SIGNATURE, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_SIGNATURE, P1_SET_SIGNATURE, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverSetClientSignature", dependsOnGroups = "serverGetModulus")
    public void serverSetClientSignatureMultiSigTwiceSwap() throws Exception {
        serverGetModulus();

        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_SIGNATURE, P1_SET_SIGNATURE, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_SIGNATURE, P1_SET_SIGNATURE, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_SIGNATURE, P1_SET_SIGNATURE, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_SIGNATURE, P1_SET_SIGNATURE, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverSetClientSignature", dependsOnGroups = "serverGetModulus")
    public void serverSetClientSignature() throws Exception {
        serverGetModulus();

        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_SIGNATURE, P1_SET_MESSAGE, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0xA2}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_SIGNATURE, P1_SET_MESSAGE, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0xA3}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_SIGNATURE, P1_SET_SIGNATURE, P2_DIVIDED | P2_PART_0, new byte[]{(byte) 0xA4}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_SIGNATURE, P1_SET_SIGNATURE, P2_DIVIDED | P2_PART_1, new byte[]{(byte) 0x2A}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverSign", dependsOnGroups = "serverSetClientSignature")
    public void serverSignNoKey() throws Exception {
        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SIGNATURE, NONE, NONE
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_CONDITIONS_NOT_SATISFIED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverSign", dependsOnGroups = "serverSetClientSignature")
    public void serverSignNoClientKey() throws Exception {
        serverGenerateKeys();

        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SIGNATURE, NONE, NONE
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_CONDITIONS_NOT_SATISFIED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverSign", dependsOnGroups = "serverSetClientSignature")
    public void serverSignNoPublicModulus() throws Exception {
        serverSetKeys();

        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SIGNATURE, NONE, NONE
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_CONDITIONS_NOT_SATISFIED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverSign", dependsOnGroups = "serverSetClientSignature")
    public void serverSignNoClientSignature() throws Exception {
        serverGetModulus();

        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SIGNATURE, NONE, NONE
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_CONDITIONS_NOT_SATISFIED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverSign", dependsOnGroups = "serverSetClientSignature")
    public void serverSignPartialMessage() throws Exception {
        serverSetClientSignatureSingleMsg();

        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SIGNATURE, NONE, NONE
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_CONDITIONS_NOT_SATISFIED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    private void prepareForServerSign() throws Exception {
        ResponseAPDU res;

        do {
            res = server.transmit(new CommandAPDU(
                    CLA_RSA_SMPC_SERVER, INS_RESET, NONE, NONE
            ));
            Assert.assertNotNull(res);
            Assert.assertEquals(SW_NO_ERROR, res.getSW());
            Assert.assertEquals(0, res.getData().length);

            res = server.transmit(new CommandAPDU(CLA_RSA_SMPC_SERVER, INS_GENERATE_KEYS, NONE, NONE));
            Assert.assertNotNull(res);
            Assert.assertEquals(SW_NO_ERROR, res.getSW());
            Assert.assertEquals(0, res.getData().length);

            res = server.transmit(new CommandAPDU(
                    CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_KEYS, P1_SET_D1_SERVER, P2_DIVIDED | P2_PART_0,
                    Util.hexStringToByteArray("7CBE4EFB4D2FFE8320295EF180E5EE6536CBCD4AB6681F85DE37D3E69B730E8A27D6FBE26493422DCEDE6C8AAF1CC2D52BC3DE27525C096A3F898C66ED37891486FA600AA33829962C1DB3F31169A55745DB6B9007AE70C844EED356DE7EBD5BA908096910F648C3431BD9196F87140B91866C17EF02242E37A12D01A81264B353B223A9FBACEDA04E027BCAAC0B85F65EB1BA748DC526CDC66AF4175B3FA74BC65593A8B5A7A0A258C568BFF36A1A799FAE58820D5BB26B03EBA8CDEB4AE6C290C42EA63FFE30F059D50169683510780657CAF5D7264FA26BBA86F2BE71046803299779E6FC7E7DC4F005660F0572F044B4E95F027F75EC09DB3C05120EF5")
            ));
            Assert.assertNotNull(res);
            Assert.assertEquals(SW_NO_ERROR, res.getSW());
            Assert.assertEquals(0, res.getData().length);

            res = server.transmit(new CommandAPDU(
                    CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_KEYS, P1_SET_D1_SERVER, P2_DIVIDED | P2_PART_1,
                    Util.hexStringToByteArray("30")
            ));
            Assert.assertNotNull(res);
            Assert.assertEquals(SW_NO_ERROR, res.getSW());
            Assert.assertEquals(0, res.getData().length);

            res = server.transmit(new CommandAPDU(
                    CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_KEYS, P1_SET_N1, P2_DIVIDED | P2_PART_0,
                    Util.hexStringToByteArray("29B4EB26E2BC20C0941F10FCE3C11367A61F008A253404B6CDF5F655658616E3BD5876B8C2106EDB260D13C49B4AFDE78EEC14D346BB4ACA985C4E2445B6C4309F301C54B242E50A3F0DB537A4D14DF1B1E8F9D89140289F71FC63D876156058B2273457168A76BD92ECEB263E8F789A2025348A0ADA4E173B0552F619992CF2A90BE63492A29F136C7147411CF4FFD34374712A5E6705E6D85596E36E31622EC9ED7671B4EE688C6972C6C0554298F75C0D86451460FFAC5B18CF0AB30B3C783F7526AB230ABEAAB7CC6685470736D3F9F762034A4DBF7620982AF623DCF04CD87D4B93E92472BD1B6F329054951A2E3A7046707E14772E9D689E77660BD9")
            ));
            Assert.assertNotNull(res);
            Assert.assertEquals(SW_NO_ERROR, res.getSW());
            Assert.assertEquals(0, res.getData().length);

            res = server.transmit(new CommandAPDU(
                    CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_KEYS, P1_SET_N1, P2_DIVIDED | P2_PART_1,
                    Util.hexStringToByteArray("CB")
            ));
            Assert.assertNotNull(res);
            Assert.assertEquals(SW_NO_ERROR, res.getSW());
            Assert.assertEquals(0, res.getData().length);

            res = server.transmit(new CommandAPDU(CLA_RSA_SMPC_SERVER, INS_GET_PUBLIC_MODULUS, NONE, P2_PART_0));
            Assert.assertNotNull(res);
        } while (res.getSW() == SW_WRONG_LENGTH);

        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(CLIENT_ARR_LENGTH, res.getData().length);

        res = server.transmit(new CommandAPDU(CLA_RSA_SMPC_SERVER, INS_GET_PUBLIC_MODULUS, NONE, P2_PART_1));
        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(CLIENT_ARR_LENGTH, res.getData().length);

        res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_SIGNATURE, P1_SET_MESSAGE, P2_PART_0,
                Util.hexStringToByteArray("F9822B96C3DCCA942368507AEAAD9C57267E6DAB7EE42DFAF7DBBD2D499A75D623C65479217D89764923987FEFD20ECC3EAF1247F09A7C3060091A4CA1251816F3E7C532894A42A1BE3BDD0BBD1985F69E6784195CC7F9E45A9BE6A4C80DC5DB0CA7B08A")
        ));
        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_SIGNATURE, P1_SET_SIGNATURE, P2_DIVIDED | P2_PART_0,
                Util.hexStringToByteArray("C4BCB85B0AC228B275B7514E4AB849F0F6CC042F3EF50923A24BDFA5EA72B1CF7EE4DB5194B8306F36A9C935139F788DCF6DAC5EB1FB8A0F7C33C108E2D71A501FF5BCE6BF3FBFE6225D0C71C65338973AF041F127336D79124779980DD20E9BB3EC47FD3746A7FBB5D7AB2029F6537A2FFD9930BC958FFA04BC8DECB33D621592A43DDBE88DE76F2801547F41EF4F5F04CC00F36E7F7EA022DE8B858805C9A3F3FD9AC9026E7C01071030B0A82DA2CEF12B47484763FDF7C0E64B8203CF4BEBAB1D9AEF880E8A996408C85C5F9E5450B07826A223CA458D348AB814E318030F3BB2B8308C7CC02E83F803BEA4318CD684E614CF963BF130F3D4B19A05105B")
        ));
        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SET_CLIENT_SIGNATURE, P1_SET_SIGNATURE, P2_DIVIDED | P2_PART_1,
                Util.hexStringToByteArray("0D")
        ));
        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverSign", dependsOnGroups = "serverSetClientSignature")
    public void serverSignBadP1P2() throws Exception {
        prepareForServerSign();

        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SIGNATURE, 0xFF, NONE
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SIGNATURE, NONE, 0xFF
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverSign", dependsOnGroups = "serverSetClientSignature")
    public void serverSignSimple() throws Exception {
        prepareForServerSign();

        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SIGNATURE, NONE, NONE
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverSign", dependsOnGroups = "serverSetClientSignature")
    public void serverSignMulti() throws Exception {
        prepareForServerSign();

        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SIGNATURE, NONE, NONE
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_SIGNATURE, NONE, NONE
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverGetSignature", dependsOnGroups = "serverSign")
    public void serverGetSignatureWithoutSigning() throws Exception {
        serverGetModulus();

        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_GET_SIGNATURE, NONE, NONE, CLIENT_ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_CONDITIONS_NOT_SATISFIED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverGetSignature", dependsOnGroups = "serverSign")
    public void serverGetSignatureWrongP1() throws Exception {
        serverSignSimple();

        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_GET_SIGNATURE, 0xFF, NONE, CLIENT_ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverGetSignature", dependsOnGroups = "serverSign")
    public void serverGetSignatureWrongP2() throws Exception {
        serverSignSimple();

        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_GET_SIGNATURE, NONE, 0xFF, CLIENT_ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test(groups = "serverGetSignature", dependsOnGroups = "serverSign")
    public void serverGetSignature() throws Exception {
        serverSignSimple();

        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_GET_SIGNATURE, NONE, P2_PART_0, CLIENT_ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(CLIENT_ARR_LENGTH, res.getData().length);

        res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_GET_SIGNATURE, NONE, P2_PART_1, CLIENT_ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(CLIENT_ARR_LENGTH, res.getData().length);
    }

    @Test(groups = "serverGetSignature", dependsOnGroups = "serverSign")
    public void serverGetSignaturePart1Twice() throws Exception {
        serverSignSimple();

        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_GET_SIGNATURE, NONE, P2_PART_0, CLIENT_ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(CLIENT_ARR_LENGTH, res.getData().length);

        res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_GET_SIGNATURE, NONE, P2_PART_0, CLIENT_ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(CLIENT_ARR_LENGTH, res.getData().length);
    }

    @Test(groups = "serverGetSignature", dependsOnGroups = "serverSign")
    public void serverGetSignaturePart2Twice() throws Exception {
        serverSignSimple();

        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_GET_SIGNATURE, NONE, P2_PART_1, CLIENT_ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(CLIENT_ARR_LENGTH, res.getData().length);

        res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_GET_SIGNATURE, NONE, P2_PART_1, CLIENT_ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(CLIENT_ARR_LENGTH, res.getData().length);
    }

    @Test(groups = "serverGetSignature", dependsOnGroups = "serverSign")
    public void serverGetSignatureSwap() throws Exception {
        serverSignSimple();

        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_GET_SIGNATURE, NONE, P2_PART_1, CLIENT_ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(CLIENT_ARR_LENGTH, res.getData().length);

        res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_GET_SIGNATURE, NONE, P2_PART_0, CLIENT_ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(CLIENT_ARR_LENGTH, res.getData().length);
    }

    @Test(groups = "serverGetSignature", dependsOnGroups = "serverSign")
    public void serverGetSignatureTwice() throws Exception {
        serverSignSimple();

        ResponseAPDU res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_GET_SIGNATURE, NONE, P2_PART_0, CLIENT_ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(CLIENT_ARR_LENGTH, res.getData().length);

        res = server.transmit(new CommandAPDU(
                CLA_RSA_SMPC_SERVER, INS_GET_SIGNATURE, NONE, P2_PART_1, CLIENT_ARR_LENGTH
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_NO_ERROR, res.getSW());
        Assert.assertEquals(CLIENT_ARR_LENGTH, res.getData().length);
    }

    @Test(groups = "serverStressTest", dependsOnGroups = "serverGetSignature")
    public void serverStressTest() throws Exception {
        System.out.println("This test requires the reference 'smpc_rsa' in the tests (../) folder.");

        ProcessBuilder clientGenerate = new ProcessBuilder("./../smpc_rsa", "client", "generate").directory(new File(TEST_PATH));
        ProcessBuilder clientSign = new ProcessBuilder("./../smpc_rsa", "client", "sign").directory(new File(TEST_PATH));
        ProcessBuilder serverVerify = new ProcessBuilder("./../smpc_rsa", "server", "verify").directory(new File(TEST_PATH));

        server.setDebug(false);

        int nokGenCount = 0;
        int nokSignCount = 0;

        System.out.println("Runs the applet against reference implementation.");
        System.out.println("Each test may fail only when the modulus is unusable.");
        System.out.println("Due to a bug in emulator, the test may very rarely fail with a wrong signature.");

        for (int i = 1; i <= TEST_COUNT; i++) {
            System.out.printf("TEST %d: ", i);
            System.out.flush();

            serverResetCard();

            Process clientGenProc = clientGenerate.start();
            OutputStreamWriter outputStreamWriter = new OutputStreamWriter(
                    new BufferedOutputStream(clientGenProc.getOutputStream())
            );
            outputStreamWriter.write("y\n");
            outputStreamWriter.flush();

            Assert.assertEquals(0, clientGenProc.waitFor());
            Assert.assertEquals(0, clientSign.start().waitFor());

            ResponseAPDU responseAPDU = server.generateKeys();
            Assert.assertEquals(SW_NO_ERROR, responseAPDU.getSW());
            Assert.assertEquals(0, responseAPDU.getData().length);

            server.setClientKeys();

            int ret = server.getPublicModulus().get(0).getSW();
            if (ret != SW_NO_ERROR) {
                System.out.println("\u001B[1;31mNOK\u001B[0m");

                if (ret == SW_WRONG_LENGTH) {
                    System.out.println("Modulus generated is not a 4096-bit number!");
                    nokGenCount++;
                    continue;
                }

                System.err.printf("SW: %04X", ret);
                Assert.fail();
            }

            responseAPDU = server.signMessage();
            Assert.assertNotNull(responseAPDU);
            ret = responseAPDU.getSW();
            if (ret != SW_NO_ERROR) {
                System.out.println("\u001B[1;31mNOK\u001B[0m");

                if (ret == SW_WRONG_DATA) {
                    System.out.println("Fraudulent or corrupt signature detected!");
                    nokSignCount++;
                    continue;
                }

                System.err.printf("SW: %04X", ret);
                Assert.fail();
            }

            Assert.assertEquals(SW_NO_ERROR, responseAPDU.getSW());

            Assert.assertEquals(0, serverVerify.start().waitFor());
            System.out.println("\u001B[1;32mOK\u001B[0m");
        }

        System.out.printf("Result: Generate/Sign/All: %d/%d/%d (%.02f %% failed)",
                nokGenCount, nokSignCount, TEST_COUNT, (double) (nokGenCount + nokSignCount) * 100 / TEST_COUNT
        );
    }

}
