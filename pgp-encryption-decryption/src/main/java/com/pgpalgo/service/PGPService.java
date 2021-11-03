package com.pgpalgo.service;

import org.bouncycastle.openpgp.PGPException;

import java.io.IOException;

public interface PGPService {

    String encryptData(String encryptionKey, String data) throws PGPException, IOException;

    String decryptData(String certName, String password, String pgpEncryptedData) throws IOException, PGPException;
}
