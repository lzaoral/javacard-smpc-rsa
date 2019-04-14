package tests;

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
    public void simpleSign() throws Exception {
        SimpleAPDU simpleAPDU = new SimpleAPDU();

        ResponseAPDU responseAPDU = simpleAPDU.generateKeys();
        Assert.assertEquals(0x9000, responseAPDU.getSW());
        Assert.assertEquals(0, responseAPDU.getData().length);

        simpleAPDU.getKeys();

        responseAPDU = simpleAPDU.signMessage();
        Assert.assertEquals(0x9000, responseAPDU.getSW());

        /*
        for (int i = 1; i <= TEST_COUNT; i++) {
            System.out.print("TEST" + i +": ");
            final ResponseAPDU responseAPDU = simpleAPDU.test();
            Assert.assertNotNull(responseAPDU);
            Assert.assertEquals(0x9000, responseAPDU.getSW());
            System.out.println("OK");
        }
        */
    }
}
