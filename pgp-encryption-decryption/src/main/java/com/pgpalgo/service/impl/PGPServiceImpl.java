package com.pgpalgo.service.impl;

import com.pgpalgo.utility.PGPUtil;
import com.pgpalgo.config.FilesConfigProperties;
import com.pgpalgo.service.PGPService;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.Streams;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;

@Service
public class PGPServiceImpl implements PGPService {
    @Autowired
    FilesConfigProperties filesConfigProperties;

    @Override
    public String encryptData(String pgpPublicKeyFileName, String data) throws PGPException, IOException {
        Security.addProvider(new BouncyCastleProvider());
        PGPPublicKey pgpPublicKey = PGPUtil.getPgpPublicKey(filesConfigProperties.getPublicKeyFilePath() + "/" + pgpPublicKeyFileName);
        PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
                new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                        .setWithIntegrityPacket(true)
                        .setSecureRandom(new SecureRandom()).setProvider("BC"));
        encGen.addMethod(
                new JcePublicKeyKeyEncryptionMethodGenerator(pgpPublicKey)
                        .setProvider("BC"));
        ByteArrayOutputStream encOut = new ByteArrayOutputStream();
        // create an indefinite length encrypted stream
        OutputStream cOut = encGen.open(encOut, new byte[4096]);
        // write out the literal data
        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
        OutputStream pOut = lData.open(
                cOut, PGPLiteralData.BINARY,
                PGPLiteralData.CONSOLE, Strings.toByteArray(data).length, new Date());
        pOut.write(Strings.toByteArray(data));
        pOut.close();
        // finish the encryption
        cOut.close();
        return Base64.encodeBase64String(encOut.toByteArray());
    }

    @Override
    public String decryptData(String certName, String password, String pgpEncryptedData) throws IOException, PGPException {
        Security.addProvider(new BouncyCastleProvider());
        PGPPrivateKey privateKey = PGPUtil.getPrivateKey(filesConfigProperties.getPublicKeyFilePath() + "/" + certName, password);
        PGPObjectFactory pgpFact = new JcaPGPObjectFactory(Base64.decodeBase64(pgpEncryptedData));
        PGPEncryptedDataList encList = (PGPEncryptedDataList) pgpFact.nextObject();
        // find the matching public key encrypted data packet.
        PGPPublicKeyEncryptedData encData = null;
        for (PGPEncryptedData pgpEnc : encList) {
            PGPPublicKeyEncryptedData pkEnc
                    = (PGPPublicKeyEncryptedData) pgpEnc;
            if (pkEnc.getKeyID() == privateKey.getKeyID()) {
                encData = pkEnc;
                break;
            }
        }
        if (encData == null) {
            throw new IllegalStateException("matching encrypted data not found");
        }
        // build decryptor factory
        PublicKeyDataDecryptorFactory dataDecryptorFactory =
                new JcePublicKeyDataDecryptorFactoryBuilder()
                        .setProvider("BC")
                        .build(privateKey);
        InputStream clear = encData.getDataStream(dataDecryptorFactory);
        byte[] literalData = Streams.readAll(clear);
        clear.close();
        // check data decrypts okay
        if (encData.verify()) {
            // parse out literal data
            PGPObjectFactory litFact = new JcaPGPObjectFactory(literalData);
            PGPLiteralData litData = (PGPLiteralData) litFact.nextObject();
            byte[] data = Streams.readAll(litData.getInputStream());
            return Strings.fromByteArray(data);
        }
        throw new IllegalStateException("modification check failed");
    }
}
