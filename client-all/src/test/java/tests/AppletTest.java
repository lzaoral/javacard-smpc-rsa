package tests;

import cardTools.Util;
import org.junit.Assert;
import org.testng.annotations.*;

import javax.crypto.Cipher;
import javax.smartcardio.ResponseAPDU;
import java.io.*;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Arrays;

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
    }

    @Test
    public void signStressTest() throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        for (int i = 1; i <= TEST_COUNT; i++) {
            System.out.print("TEST" + i +": ");

            SimpleAPDU simpleAPDU = new SimpleAPDU();
            ResponseAPDU responseAPDU = simpleAPDU.generateKeys();
            Assert.assertEquals(0x9000, responseAPDU.getSW());
            Assert.assertEquals(0, responseAPDU.getData().length);

            simpleAPDU.getKeys();

            responseAPDU = simpleAPDU.signMessage();
            Assert.assertNotNull(responseAPDU);
            Assert.assertEquals(0x9000, responseAPDU.getSW());

            ProcessBuilder server = new ProcessBuilder("./main_server");
            server.redirectError(ProcessBuilder.Redirect.INHERIT);
            //server.redirectOutput(ProcessBuilder.Redirect.INHERIT);

            Process serverProc = server.start();

            try (OutputStream stdin = serverProc.getOutputStream()) {
                stdin.write("1\ny\n2\n0\n".getBytes());
                stdin.flush();
            }

            serverProc.waitFor();
            System.out.println(serverProc.exitValue() == 0 ? "OK" : "NOK");
        }
    }
}
