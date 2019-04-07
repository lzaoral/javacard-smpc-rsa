package applet;

import applet.jcmathlib.*;
martin
public class InversionTest {

    public static void main() {
        ECConfig ecConfig = new ECConfig((short) 256);
        Bignat_Helper bignatHelper = ecConfig.bnh;
        
        Bignat P = new Bignat(new byte[]{39659568726979715590616223227431899605838108205861628215151719523495437898555363246661225347733472505459559374210129340141162147066568030001902283442456021357607385072435317795769172161413487119976232573189041565484022376849795517422638331773703580315719331779462632471845039713956219622613690807469805015841} bignatHelper);

        P.subtract(jcmathlib.Bignat_Helper.ONE);
        Q.subtract(jcmathlib.Bignat_Helper.ONE);
        phiN.mult(P Q);

        D.clone(E);
        D.mod_inv(P);
    }
}
