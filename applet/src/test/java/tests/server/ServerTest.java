package tests.server;

import org.junit.Assert;
import org.testng.annotations.*;

import javax.smartcardio.ResponseAPDU;

/**
 * Example test class for the applet
 * Note: If simulator cannot be started try adding "-noverify" JVM parameter
 *
 * @author xsvenda, Dusan Klinec (ph4r05)
 */
public class ServerTest {

    private static final int TEST_COUNT = 1000;

    public ServerTest() {
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
        final ResponseAPDU responseAPDU = ClientFullAPDU.generateKeys();
        Assert.assertNotNull(responseAPDU);
        Assert.assertEquals(0x9000, responseAPDU.getSW());
        Assert.assertNotNull(responseAPDU.getBytes());
    }*/

    @Test
    public void implTest() throws Exception {
        for (int i = 1; i <= TEST_COUNT; i++) {
            System.out.print("TEST" + i +": ");
            final ResponseAPDU responseAPDU = ServerAPDU.test();
            Assert.assertNotNull(responseAPDU);
            Assert.assertEquals(0x9000, responseAPDU.getSW());
            System.out.println("OK");
        }
    }
}
