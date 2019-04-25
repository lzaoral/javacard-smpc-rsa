package tests;

import org.junit.Assert;

import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import javax.smartcardio.ResponseAPDU;
import java.io.OutputStream;
import java.security.Security;

/**
 * Example test class for the applet
 * Note: If simulator cannot be started try adding "-noverify" JVM parameter
 *
 * @author xsvenda, Dusan Klinec (ph4r05)
 */
public class AppletTest {

    private static final int TEST_COUNT = 200;

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
    public void signSimple() throws Exception {
        SimpleAPDU simpleAPDU = new SimpleAPDU();

        ResponseAPDU responseAPDU = simpleAPDU.generateKeys();
        Assert.assertEquals(0x9000, responseAPDU.getSW());
        Assert.assertEquals(0, responseAPDU.getData().length);

        simpleAPDU.getKeys();

        responseAPDU = simpleAPDU.signMessage();
        Assert.assertEquals(0x9000, responseAPDU.getSW());
    }

    @Test
    public void signStressTest() throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        for (int i = 1; i <= TEST_COUNT; i++) {
            System.out.printf("TEST %d: ", i);
            System.out.flush();

            SimpleAPDU simpleAPDU = new SimpleAPDU();
            ResponseAPDU responseAPDU = simpleAPDU.generateKeys();
            Assert.assertEquals(0x9000, responseAPDU.getSW());
            Assert.assertEquals(0, responseAPDU.getData().length);

            simpleAPDU.getKeys();

            responseAPDU = simpleAPDU.signMessage();
            Assert.assertNotNull(responseAPDU);
            Assert.assertEquals(0x9000, responseAPDU.getSW());

            Process serverProc = new ProcessBuilder("./main_server")
                    .redirectError(ProcessBuilder.Redirect.INHERIT).start();

            try (OutputStream stdin = serverProc.getOutputStream()) {
                stdin.write("1\ny\n2\n0\n".getBytes());
                stdin.flush();
            }

            serverProc.waitFor();
            System.err.flush();
            System.out.println(serverProc.exitValue() == 0 ? "OK" : "NOK");
        }
    }
}
