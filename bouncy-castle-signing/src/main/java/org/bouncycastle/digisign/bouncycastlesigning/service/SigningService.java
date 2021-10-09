package org.bouncycastle.digisign.bouncycastlesigning.service;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;

public interface SigningService {

  byte[] encryptData(byte[] data, X509Certificate encryptionCertificate) throws CertificateEncodingException, CMSException, IOException;

  byte[] decryptData(final byte[] encryptedData, final PrivateKey decryptionKey) throws CMSException;

  byte[] signData(byte[] data, final X509Certificate signingCertificate, final PrivateKey signingKey)
      throws CertificateEncodingException, CMSException, IOException, OperatorCreationException;

  boolean verifySignedData(final byte[] signedData)
      throws CMSException, IOException, OperatorCreationException, CertificateException;
}
