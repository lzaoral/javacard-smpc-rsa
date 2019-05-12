package tests.server;

import org.junit.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import static tests.server.ServerAPDU.*;

/**
 * Example test class for the applet
 * Note: If simulator cannot be started try adding "-noverify" JVM parameter
 *
 * @author xsvenda, Dusan Klinec (ph4r05)
 */
public class ServerTest {

    private static boolean realCard = true;
    private static int SW_OK = 0x9000;
    private ServerAPDU server;

    @BeforeClass
    public void setClass() throws Exception {
        server = new ServerAPDU(realCard);
    }

    public void setUp() throws Exception {
        server.transmit(new CommandAPDU(CLA_RSA_SMPC_SERVER, INS_RESET, 0x00, 0x00));
        server.setDebug(true);
    }

    @Test
    public void simpleSign() throws Exception {
        for (int i = 0; i < 200; ++i) {
            setUp();

            System.out.println(server.generateKeys().getSW());
            server.setClientKeys();

            if (server.getPublicModulus().get(0).getSW() != SW_OK)
                continue;

            System.out.println(server.signMessage().getSW());
        }
    }
}
