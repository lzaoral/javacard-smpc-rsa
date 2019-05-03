package tests.server;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

/**
 * Example test class for the applet
 * Note: If simulator cannot be started try adding "-noverify" JVM parameter
 *
 * @author xsvenda, Dusan Klinec (ph4r05)
 */
public class ServerTest {

    private static boolean realCard = false;
    private static int SW_OK = 0x9000;
    private ServerAPDU server;

    @BeforeClass
    public void setClass() throws Exception {
        server = new ServerAPDU(realCard);
    }

    /*@BeforeMethod
    public void setUp() throws Exception {
        client.transmit(new CommandAPDU(CLA_RSA_SMPC_CLIENT_SIGN, INS_RESET, 0x00, 0x00));
    }*/

    @Test
    public void simpleSign() throws Exception {
        server.generateKeys();
        server.setClientKeys();
        server.getPublicModulus();
        server.signMessage();
    }
}
