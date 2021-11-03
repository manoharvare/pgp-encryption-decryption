package com.pgpalgo.utility;

import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;

public class PGPUtil {
    public static PGPPublicKey getPgpPublicKey(String publicFile) throws PGPException, IOException {
        InputStream in = new FileInputStream(publicFile);
        in = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(in);

        JcaPGPPublicKeyRingCollection pgpPub = new JcaPGPPublicKeyRingCollection(in);
        in.close();

        PGPPublicKey key = null;
        Iterator<PGPPublicKeyRing> rIt = pgpPub.getKeyRings();
        while (key == null && rIt.hasNext()) {
            PGPPublicKeyRing kRing = rIt.next();
            Iterator<PGPPublicKey> kIt = kRing.getPublicKeys();
            while (key == null && kIt.hasNext()) {
                PGPPublicKey k = kIt.next();

                if (k.isEncryptionKey()) {
                    key = k;
                }
            }
        }
        return key;
    }

    public static PGPPrivateKey getPrivateKey(String privateFile,String password) throws IOException, PGPException {
        InputStream decoderStream = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(new FileInputStream(privateFile));
        PGPObjectFactory pgpF = new PGPObjectFactory(decoderStream, new JcaKeyFingerprintCalculator());
        PGPSecretKey secretKey = ((PGPSecretKeyRing) pgpF.nextObject()).getSecretKey();
        PBESecretKeyDecryptor decryptor = new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(password.toCharArray());
        PGPPrivateKey privateKey = secretKey.extractPrivateKey(decryptor);
        if (privateKey == null) {
            throw new IllegalArgumentException("Secret key for message not found.");
        }
        return privateKey;
    }

}
