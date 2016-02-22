package net.oauth.jsontoken.crypto;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentSkipListSet;

import junit.framework.TestCase;

public class RsaSHA256VerifierTest extends TestCase {

    public void testVerifySignatureInThreads() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyGen.generateKeyPair();
        Signature sig = Signature.getInstance("SHA256withRSA");
        PublicKey publicKey = keyPair.getPublic();
        sig.initSign(keyPair.getPrivate());
        final byte[] testData = "something that is signed.".getBytes("utf-8");
        sig.update(testData);
        final byte[] signature = sig.sign();
        final RsaSHA256Verifier verifier = new RsaSHA256Verifier(publicKey);
        final Set<Integer> complete = new ConcurrentSkipListSet<Integer>();
        int threads = 5000;
        for(int i = 0; i < threads ; ++i){
            final int j = i;
            Runnable r = new Runnable() {
                public void run() {
                    try {
                        verifier.verifySignature(testData, signature);
                        complete.add(j);
                    } catch (SignatureException e) {
                        complete.add(j);
                        throw new AssertionError("Could not verify signature", e);                        
                    }
                }
            };
            new Thread(r).start();
        }
        while(complete.size() < threads){
            // wait...
        }
    }
    
}
