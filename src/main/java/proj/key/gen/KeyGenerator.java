package proj.key.gen;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class KeyGenerator {
    
    public static void main(String[] args) {
       try {
           Security.addProvider(new BouncyCastleProvider());
           
           KeyPair pair = genKeys();
           String priv = getPriv(pair);
           String pub = getPub(pair);
           
           System.out.println("Private Key: " + priv);
           System.out.println("Public Key: " + pub);
       } catch (Exception e) {
           e.printStackTrace();
       }
        
    }
    
    public static KeyPair genKeys() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256k1");
        keyGen.initialize(ecSpec);
        return keyGen.generateKeyPair();
    }
    
    private static String adjustTo64(String s) {
        switch(s.length()) {
        case 62: return "00" + s;
        case 63: return "0" + s;
        case 64: return s;
        default:
            throw new IllegalArgumentException("not a valid key: " + s);
        }
    }
    
    public static String getPriv(KeyPair pair) {
        return adjustTo64(((ECPrivateKey)pair.getPrivate()).getS().toString(16));
    }
    
    public static String getPub(KeyPair pair) throws Exception {
        ECPublicKey epub = (ECPublicKey)pair.getPublic();
        ECPoint pt = epub.getW();
        String sx = adjustTo64(pt.getAffineX().toString(16));
        String sy = adjustTo64(pt.getAffineY().toString(16));
        String bcPub = "04" + sx + sy;
        
        byte[] bcPubBA = new byte[bcPub.length()/2];
        for (int i = 0; i < bcPub.length()/2; i += 2)
            bcPubBA[i / 2] = (byte) ((Character.digit(bcPub.charAt(i), 16) << 4) + Character.digit(bcPub.charAt(i+1), 16));
        
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] s1 = sha.digest(bcPubBA);
        
        MessageDigest rmd = MessageDigest.getInstance("RipeMD160", "BC");
        byte[] r1 = rmd.digest(s1);
        
        byte[] r2 = new byte[r1.length + 1];
        r2[0] = 0;
        for (int i = 0 ; i < r1.length ; i++) r2[i+1] = r1[i];

        byte[] s2 = sha.digest(r2);
        byte[] s3 = sha.digest(s2);
        
        byte[] a1 = new byte[25];
        for (int i = 0 ; i < r2.length ; i++) a1[i] = r2[i];
        for (int i = 0 ; i < 4 ; i++) a1[21 + i] = s3[i];
        
        return Base58.encode(a1);
    }

}
