package org.bouncycastle.digisign.bouncycastlesigning.service;

import java.io.IOException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.digisign.bouncycastlesigning.config.DigiSignConfig;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
public class SigningServiceImplProdTest {

  @Autowired
  private SigningServiceImpl bouncyCastleUtil;

  @Autowired
  private DigiSignConfig signConfig;

  @Test
  public void givenCryptographicResource_whenOperationSuccess_returnTrue()
      throws IOException, CertificateException, CMSException, OperatorCreationException {

    KeyStore keystore = signConfig.loadKeyStore();
    X509Certificate certificate = signConfig.loadCertificate(keystore);
    PrivateKey privateKey = signConfig.loadPrivateKey(keystore);

    String secretMessage = "My password for bouncy castle signing is password";
    System.out.println("Original Message : " + secretMessage);

    byte[] messageToEncrypt = secretMessage.getBytes();
    byte[] encryptedData = bouncyCastleUtil.encryptData(messageToEncrypt, certificate);
    String encryptedMessage = new String(encryptedData);
    System.out.println("Encrypted Message : " + encryptedMessage);
    byte[] decryptedRawData = bouncyCastleUtil.decryptData(encryptedData, privateKey);
    String decryptedMessage = new String(decryptedRawData);

    System.out.println("Decrypted Message : " + decryptedMessage);
    assertEquals(decryptedMessage, secretMessage);

    byte[] signedData = bouncyCastleUtil.signData(secretMessage.getBytes(), certificate, privateKey);
    System.out.println("Signed Message : " + new String(signedData));
    boolean check = bouncyCastleUtil.verifySignedData(signedData);
    assertTrue(check);
  }
}
