package org.bouncycastle.digisign.bouncycastlesigning.service;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
public class SigningServiceImplTest {

    String certificatePath = "src/main/resources/message-signing-public-certificate.cer";
    String privateKeyPath = "src/main/resources/message-signing-keystore.jks";
    char[] p12Password = "password".toCharArray();
    char[] keyPassword = "password".toCharArray();

    @Autowired
    private SigningServiceImpl bouncyCastleUtil;

    @Test
    public void givenCryptographicResource_whenOperationSuccess_returnTrue()
            throws NoSuchAlgorithmException, IOException, KeyStoreException, UnrecoverableKeyException,
            CertificateException, NoSuchProviderException, CMSException, OperatorCreationException {

        CertificateFactory certFactory = CertificateFactory.getInstance("X.509", "BC");
        X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(new FileInputStream(certificatePath));
        KeyStore keystore = KeyStore.getInstance("PKCS12");
        keystore.load(new FileInputStream(privateKeyPath), p12Password);
        PrivateKey privateKey = (PrivateKey) keystore.getKey("message-signing", keyPassword);

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
