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

    // Example test
    /*@Test
    public void hello() throws Exception {
        final ResponseAPDU responseAPDU = SimpleAPDU.generateKeys();
        Assert.assertNotNull(responseAPDU);
        Assert.assertEquals(0x9000, responseAPDU.getSW());
        Assert.assertNotNull(responseAPDU.getBytes());
    }*/

    @Test
    public void implTest() throws Exception {
        for (int i = 1; i <= TEST_COUNT; i++) {
            System.out.print("TEST" + i +": ");
            final ResponseAPDU responseAPDU = SimpleAPDU.test();
            Assert.assertNotNull(responseAPDU);
            Assert.assertEquals(0x9000, responseAPDU.getSW());
            System.out.println("OK");
        }
    }
}
