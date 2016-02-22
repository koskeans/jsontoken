package net.oauth.jsontoken.crypto;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Set;
import java.util.concurrent.ConcurrentSkipListSet;

import junit.framework.TestCase;

public class RsaSHA256VerifierTest extends TestCase {

    private byte[] testDatas;
    private byte[] signatures;
    private RsaSHA256Verifier verifier;

    public void testVerifySignatureInThreads() throws Exception {
        final Set<Integer> complete = new ConcurrentSkipListSet<Integer>();
        int threads = 5000;
        for(int i = 0; i < threads ; ++i){
            final int j = i;
            new Thread(new Runnable() {
                public void run() {
                    try {
                        verifier.verifySignature(testDatas, signatures);
                        complete.add(j);
                    } catch (SignatureException e) {
                        complete.add(j);
                        throw new AssertionError("Could not verify signature", e);                        
                    }
                }
            }).start();
        }
        while(complete.size() < threads){
            // wait...
        }
    }
    
    public void testVerifySignature() throws Exception {
        verifier.verifySignature(testDatas, signatures);
    }

    protected void setUp()
            throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, SignatureException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyGen.generateKeyPair();
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(keyPair.getPrivate());
        testDatas = "something that is signed.".getBytes("utf-8");
        sig.update(testDatas);
        signatures = sig.sign();
        verifier = new RsaSHA256Verifier(keyPair.getPublic());
    }
    
}
