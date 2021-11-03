package com.pgpalgo.rest;

import com.pgpalgo.service.PGPService;
import org.bouncycastle.openpgp.PGPException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;


@RestController
public class PGPEncryptionDecryptionController {

    private final PGPService pgpService;

    public PGPEncryptionDecryptionController(PGPService pgpService) {
        this.pgpService = pgpService;
    }

    @GetMapping("/encryption")
    public String encrypt(@RequestHeader("certName") String certName,
                          @RequestHeader("requestMessage") String requestData) throws PGPException, IOException {
        return pgpService.encryptData(certName, requestData);
    }

    @GetMapping("/decryption")
    public String decrypt(@RequestHeader("Certname") String certName,
                          @RequestHeader("Password") String password,
                          @RequestHeader("requestMessage") String requestMessage) throws PGPException, IOException {
        return pgpService.decryptData(certName, password,requestMessage);
    }
}
