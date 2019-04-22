package tests;

import cardTools.Util;
import javacard.framework.ISO7816;
import org.junit.Assert;
import org.testng.annotations.*;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import static tests.SimpleAPDU.*;

/**
 * Example test class for the applet
 * Note: If simulator cannot be started try adding "-noverify" JVM parameter
 *
 * @author xsvenda, Dusan Klinec (ph4r05), Lukas Zaoral
 */
public class AppletTest {

    private static int SW_OK = 0x9000;
    private static boolean realCard = false;
    private SimpleAPDU simpleAPDU;

    @BeforeClass
    public void setClass() throws Exception {
        simpleAPDU = new SimpleAPDU(realCard);
    }

    @BeforeMethod
    public void setUp() throws Exception {
        simpleAPDU.transmit(new CommandAPDU(CLA_RSA_SMPC_CLIENT, INS_RESET, 0x00, 0x00));
    }

    @Test
    public void wrongCLA() throws Exception {
        ResponseAPDU res = simpleAPDU.transmit(new CommandAPDU(
                0xFF, 0x00, 0x00, 0x00
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(ISO7816.SW_CLA_NOT_SUPPORTED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void wrongINS() throws Exception {
        ResponseAPDU res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, 0xFF, 0x00, 0x00
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(ISO7816.SW_INS_NOT_SUPPORTED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void wrongSetKeysP1() throws Exception {
        ResponseAPDU res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_KEYS, 0xFF, 0x02
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(ISO7816.SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void wrongSetKeysP2Low() throws Exception {
        ResponseAPDU res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_KEYS, 0x00, 0x0F
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(ISO7816.SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }


    @Test
    public void wrongSetKeysP2High() throws Exception {
        ResponseAPDU res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_KEYS, 0x00, 0xF0
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(ISO7816.SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void setSingleD() throws Exception {
        ResponseAPDU res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_KEYS, P1_SET_D, PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void setMultiD() throws Exception {
        ResponseAPDU res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_KEYS, P1_SET_D, MULTI_PART | PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_KEYS, P1_SET_D,MULTI_PART | PART_1, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void setSingleN() throws Exception {
        setSingleD();
        ResponseAPDU res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_KEYS, P1_SET_N, PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void setMultiN() throws Exception {
        setSingleD();
        ResponseAPDU res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_KEYS, P1_SET_N, MULTI_PART | PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_KEYS, P1_SET_N, MULTI_PART | PART_1, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void resetSingleD() throws Exception {
        setSingleD();
        ResponseAPDU res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_KEYS, P1_SET_D, PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(ISO7816.SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void resetMultiD() throws Exception {
        setMultiD();
        ResponseAPDU res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_KEYS, P1_SET_D, PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(ISO7816.SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void setNBeforeD() throws Exception {
        ResponseAPDU res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_KEYS, P1_SET_N, PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(ISO7816.SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void resetSingleN() throws Exception {
        setSingleN();

        ResponseAPDU res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_KEYS, P1_SET_N, PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(ISO7816.SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void resetMultiN() throws Exception {
        setMultiN();
        ResponseAPDU res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_KEYS, P1_SET_N, PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(ISO7816.SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void setDMultiTwice() throws Exception {
        ResponseAPDU res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_KEYS, P1_SET_D, MULTI_PART | PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_KEYS, P1_SET_D, MULTI_PART | PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(ISO7816.SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_KEYS, P1_SET_D, MULTI_PART | PART_1, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_KEYS, P1_SET_D, MULTI_PART | PART_1, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(ISO7816.SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void setDMultiSwitched() throws Exception {
        ResponseAPDU res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_KEYS, P1_SET_D, MULTI_PART | PART_1, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_KEYS, P1_SET_D, MULTI_PART | PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void setNMultiSwitched() throws Exception {
        setSingleD();
        ResponseAPDU res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_KEYS, P1_SET_N, MULTI_PART | PART_1, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_KEYS, P1_SET_N, MULTI_PART | PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void setNMultiTwice() throws Exception {
        setSingleD();

        ResponseAPDU res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_KEYS, P1_SET_N, MULTI_PART | PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_KEYS, P1_SET_N, MULTI_PART | PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(ISO7816.SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_KEYS, P1_SET_N, MULTI_PART | PART_1, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_KEYS, P1_SET_N, MULTI_PART | PART_1, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(ISO7816.SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void setNMultiTwiceSwap() throws Exception {
        setSingleD();

        ResponseAPDU res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_KEYS, P1_SET_N, MULTI_PART | PART_1, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_KEYS, P1_SET_N, MULTI_PART | PART_1, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(ISO7816.SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_KEYS, P1_SET_N, MULTI_PART | PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_KEYS, P1_SET_N, MULTI_PART | PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(ISO7816.SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void setKeys() throws Exception {
        ResponseAPDU res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_KEYS, P1_SET_D, PART_0, new byte[]{(byte) 0xF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_KEYS, P1_SET_N, PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void setInitialisedKeys() throws Exception {
        setKeys();

        ResponseAPDU res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_KEYS, 0x00, 0x00
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(ISO7816.SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void resetKeys() throws Exception {
        setKeys();

        ResponseAPDU res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_RESET, 0x00, 0x00
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        setKeys();
    }

    @Test
    public void resetWrongP1() throws Exception {
        setKeys();

        ResponseAPDU res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_RESET, 0xFF, 0x00
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(ISO7816.SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_KEYS, 0x00, 0x00
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(ISO7816.SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void resetWrongP2() throws Exception {
        setKeys();

        ResponseAPDU res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_RESET, 0x00, 0xFF
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(ISO7816.SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_KEYS, 0x00, 0x00
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(ISO7816.SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void setMessageNoKeys() throws Exception {
        ResponseAPDU res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x00, PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(ISO7816.SW_CONDITIONS_NOT_SATISFIED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void setSimpleMessage() throws Exception {
        setKeys();

        ResponseAPDU res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x00, PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void setMultipartMessage() throws Exception {
        setKeys();

        ResponseAPDU res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x00, MULTI_PART | PART_0, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x00, MULTI_PART | PART_1, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void setMultipartMessageTwice() throws Exception {
        setKeys();

        ResponseAPDU res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x00, MULTI_PART | PART_0, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x00, MULTI_PART | PART_0, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(ISO7816.SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x00, MULTI_PART | PART_1, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x00, MULTI_PART | PART_1, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void setMultipartMessageTwiceSwap() throws Exception {
        setKeys();

        ResponseAPDU res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x00, MULTI_PART | PART_1, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x00, MULTI_PART | PART_1, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(ISO7816.SW_COMMAND_NOT_ALLOWED, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x00, MULTI_PART | PART_0, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x00, MULTI_PART | PART_0, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void resetMessage() throws Exception {
        setKeys();

        ResponseAPDU res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x00, PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x00, PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void resetMultipartMessage() throws Exception {
        setKeys();

        ResponseAPDU res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x00, MULTI_PART | PART_0, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x00, MULTI_PART | PART_1, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x00, MULTI_PART | PART_0, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x00, MULTI_PART | PART_1, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void setMultipartMessageSwap() throws Exception {
        setKeys();

        ResponseAPDU res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x00, MULTI_PART | PART_1, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x00, MULTI_PART | PART_0, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void setMessageIncorrectP1() throws Exception {
        setKeys();
        ResponseAPDU res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x01, PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(ISO7816.SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x00, PART_1, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(ISO7816.SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void signNoKey() throws Exception {
        ResponseAPDU res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SIGNATURE, 0x00, 0x00
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(ISO7816.SW_CONDITIONS_NOT_SATISFIED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void signNoMessage() throws Exception {
        setKeys();

        ResponseAPDU res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SIGNATURE, 0x00, 0x00
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(ISO7816.SW_CONDITIONS_NOT_SATISFIED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void signPartialMessage() throws Exception {
        setKeys();

        ResponseAPDU res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x00, MULTI_PART | PART_0, new byte[]{(byte) 0xFF}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SIGNATURE, 0x00, 0x00
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(ISO7816.SW_CONDITIONS_NOT_SATISFIED, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void signBadP1P2() throws Exception {
        setSimpleMessage();

        ResponseAPDU res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SIGNATURE, 0xFF, 0xFF
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(ISO7816.SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SIGNATURE, 0x00, 0xFF
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(ISO7816.SW_INCORRECT_P1P2, res.getSW());
        Assert.assertEquals(0, res.getData().length);
    }

    @Test
    public void signMultipartMessage() throws Exception {
        simpleAPDU.setKeys();

        ResponseAPDU res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x00, MULTI_PART | PART_0, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SET_MESSAGE, 0x00, MULTI_PART | PART_1, new byte[]{(byte) 0x0F}
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(0, res.getData().length);

        res = simpleAPDU.transmit(new CommandAPDU(
                CLA_RSA_SMPC_CLIENT, INS_SIGNATURE, 0x00, 0x00, CLIENT_ARR_LEN
        ));

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals(256, res.getData().length);
        Assert.assertArrayEquals(Util.hexStringToByteArray("759A9B5DFFE2831356239D9CBFC8BB3CB8DB5DE9EF25A85E60E49EF940BC6844FD8AF286A507550CE9C81F5212E6D7154CE54B4C285C65EAA8C9070FE4AE030B5A73398AC6E62B13F014E81A85865CAA25D94A1CCA9791CEE6616AC73DC1D38E9BC8B9AD38D7DAF9943BCBC1A6C071DFC451A26E9CAF7DCFE91880BF07523394EB1736D223531087AF598498341E728653C0177B4C01EA4D784CE0E3554346194E31F792BAD5814D721AE202B7360D0D7F43FF485C2AEF4CA6F75A3C16E422E93F1497715E75A36CFD2801B5B1140AB89C8FCCE59E6EF5175C03DE39F9C9943141680B67FEF8A721B5C23ECD6FCF88F336D832337A99ECE7482474339056D047"),
                res.getData());
    }

    @Test
    public void simpleSign() throws Exception {
        simpleAPDU.setKeys();
        ResponseAPDU res = simpleAPDU.signMessage();

        Assert.assertNotNull(res);
        Assert.assertEquals(SW_OK, res.getSW());
        Assert.assertEquals("118D752136C31CD67A7084351A81C50B594FF9D6A0A7BCE187CCD357FC50DA172199248AC37FC8327249301A2B48495BA9653F2D7BBAD3E592C6F5FF288A479C74FA218D1127EA885A3BBDC13B94EBBAE40A52BAFEAE316982E928FF63DFA79E0B368CA2FE26E2519B8E2F83F27448590A3DE86583F3B6911DA52A6135C10912C2754863E61F7813BBD908BA5B3D79984C8F61804CB945ADD731BD243FDDF3B8ACAAF60C956AE72624F54298414C1F368E50401D84CC1C8FBE3A1F302C9E5BBF40C320EF99BDE1602F4926ECAC4C481AAA38881FB7F979D8FC1BFC6D245ADC7037E2B0F23D366DD557E8F3FE90BEDE592078363762EB5FE5971BED74A097C11E",
                Util.toHex(res.getData()));
    }
}
