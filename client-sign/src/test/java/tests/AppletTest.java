package tests;

import cardTools.Util;
import org.junit.Assert;
import org.testng.annotations.*;

import javax.smartcardio.ResponseAPDU;

/**
 * Example test class for the applet
 * Note: If simulator cannot be started try adding "-noverify" JVM parameter
 *
 * @author xsvenda, Dusan Klinec (ph4r05)
 */
public class AppletTest {

    private static final int TEST_COUNT = 1000;

    public AppletTest() {
    }

    @BeforeClass
    public static void setUpClass() throws Exception {
    }

    @AfterClass
    public static void tearDownClass() throws Exception {
    }

    @BeforeMethod
    public void setUpMethod() throws Exception {
    }

    @AfterMethod
    public void tearDownMethod() throws Exception {
    }

    @Test
    public void implTest() throws Exception {
        SimpleAPDU simpleAPDU = new SimpleAPDU();
        simpleAPDU.setKeys();
        ResponseAPDU responseAPDU = simpleAPDU.signMessage();

        Assert.assertNotNull(responseAPDU);
        Assert.assertEquals(0x9000, responseAPDU.getSW());
        Assert.assertEquals("118D752136C31CD67A7084351A81C50B594FF9D6A0A7BCE187CCD357FC50DA172199248AC37FC8327249301A2B48495BA9653F2D7BBAD3E592C6F5FF288A479C74FA218D1127EA885A3BBDC13B94EBBAE40A52BAFEAE316982E928FF63DFA79E0B368CA2FE26E2519B8E2F83F27448590A3DE86583F3B6911DA52A6135C10912C2754863E61F7813BBD908BA5B3D79984C8F61804CB945ADD731BD243FDDF3B8ACAAF60C956AE72624F54298414C1F368E50401D84CC1C8FBE3A1F302C9E5BBF40C320EF99BDE1602F4926ECAC4C481AAA38881FB7F979D8FC1BFC6D245ADC7037E2B0F23D366DD557E8F3FE90BEDE592078363762EB5FE5971BED74A097C11E",
                Util.toHex(responseAPDU.getData()));
    }

    /*
    @Test
    public void simpleSign() throws Exception {
        SimpleAPDU simpleAPDU = new SimpleAPDU();
        simpleAPDU.setKeys();

        for (int i = 1; i <= TEST_COUNT; i++) {
            System.out.print("TEST" + i +": ");
            final ResponseAPDU responseAPDU = simpleAPDU.test();
            Assert.assertNotNull(responseAPDU);
            Assert.assertEquals(0x9000, responseAPDU.getSW());
            Assert.assertEquals(0, responseAPDU.getData().length);
            System.out.println("OK");
        }
    }
    */
}
