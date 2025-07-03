package org.bouncycastle.digisign.bouncycastlesigning.service;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.digisign.bouncycastlesigning.config.DigiSignConfig;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.web.multipart.MultipartFile;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
public class SigningServiceImplProdTest {

  @Autowired
  private SigningServiceImpl signingService;

  @Autowired
  private DigiSignConfig signConfig;

  @Test
  public void givenCryptographicResource_whenEncryptionOperationSuccess_returnTrue()
      throws IOException, CertificateException, CMSException {

    KeyStore keystore = signConfig.loadKeyStore();
    X509Certificate certificate = signConfig.loadCertificate(keystore);
    PrivateKey privateKey = signConfig.loadPrivateKey(keystore);

    String secretMessage = "My password for bouncy castle signing is password";
    System.out.println("Original Message : " + secretMessage);

    byte[] messageToEncrypt = secretMessage.getBytes();
    byte[] encryptedData = signingService.encryptData(messageToEncrypt, certificate);
    String encryptedMessage = new String(encryptedData);
    System.out.println("Encrypted Message : " + encryptedMessage);
    byte[] decryptedRawData = signingService.decryptData(encryptedData, privateKey);
    String decryptedMessage = new String(decryptedRawData);

    System.out.println("Decrypted Message : " + decryptedMessage);
    assertEquals(secretMessage, decryptedMessage);
  }

  @Test
  public void givenCryptographicResource_whenSigningOperationSuccess_returnTrue()
      throws IOException, CertificateException, CMSException, OperatorCreationException {

    KeyStore keystore = signConfig.loadKeyStore();
    X509Certificate certificate = signConfig.loadCertificate(keystore);
    PrivateKey privateKey = signConfig.loadPrivateKey(keystore);

    String secretMessage = "My password for bouncy castle signing is password";
    System.out.println("Original Message : " + secretMessage);

    byte[] signedData = signingService.signData(secretMessage.getBytes(), certificate, privateKey);
    System.out.println("Signed Message : " + new String(signedData));
    boolean check = signingService.verifySignedData(signedData);
    assertTrue(check);
  }

  @Test
  public void givenCryptographicResource_whenSigningOperationOnPlainDataSuccess_returnTrue()
      throws IOException, CertificateException, CMSException, OperatorCreationException {

    KeyStore keystore = signConfig.loadKeyStore();
    X509Certificate certificate = signConfig.loadCertificate(keystore);
    PrivateKey privateKey = signConfig.loadPrivateKey(keystore);
    InputStream fileInputStream = createBatchFile().getInputStream();

    byte[] signedData = signingService.signData(IOUtils.toByteArray(fileInputStream), certificate, privateKey);

    boolean check = signingService.verifySignedData(signedData);
    assertTrue(check);
  }

  @Test
  public void givenCryptographicResource_whenSigningOperationOnHashedDataSuccess_returnTrue()
      throws IOException, CertificateException, CMSException, OperatorCreationException, NoSuchAlgorithmException {

    KeyStore keystore = signConfig.loadKeyStore();
    X509Certificate certificate = signConfig.loadCertificate(keystore);
    PrivateKey privateKey = signConfig.loadPrivateKey(keystore);
    InputStream fileInputStream = createBatchFile().getInputStream();

    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    byte[] sha256Hash = digest.digest(IOUtils.toByteArray(fileInputStream));

    byte[] signedData = signingService.signData(sha256Hash, certificate, privateKey);

    boolean check = signingService.verifySignedData(signedData);
    assertTrue(check);
  }

  public static MultipartFile createBatchFile() {
    return new MockMultipartFile("file", "hello.txt", MediaType.MULTIPART_FORM_DATA_VALUE,
        "Hello, World!".getBytes());
  }
}
