package org.bouncycastle.digisign.bouncycastlesigning.service;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.KeyTransRecipientInformation;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.springframework.stereotype.Component;

@Component
public class SigningServiceImpl implements SigningService {

    @Override
    public byte[] encryptData(final byte[] data, X509Certificate encryptionCertificate)
            throws CertificateEncodingException, CMSException, IOException {
        byte[] encryptedData = null;

        if (null != data && null != encryptionCertificate) {
            CMSEnvelopedDataGenerator cmsEnvelopedDataGenerator = new CMSEnvelopedDataGenerator();
            JceKeyTransRecipientInfoGenerator jceKey = new JceKeyTransRecipientInfoGenerator(encryptionCertificate);
            cmsEnvelopedDataGenerator.addRecipientInfoGenerator(jceKey);
            CMSTypedData message = new CMSProcessableByteArray(data);

            OutputEncryptor encryptor = new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC)
                    .setProvider("BC")
                    .build();
            CMSEnvelopedData cmsEnvelopedData = cmsEnvelopedDataGenerator.generate(message, encryptor);

            encryptedData = cmsEnvelopedData.getEncoded();
        }
        return encryptedData;
    }

    @Override
    public byte[] decryptData(final byte[] encryptedData, final PrivateKey decryptionKey) throws CMSException {
        byte[] decryptedData = null;

        if (null != encryptedData && null != decryptionKey) {
            CMSEnvelopedData envelopedData = new CMSEnvelopedData(encryptedData);
            Collection<RecipientInformation> recipientInfoCollection = envelopedData.getRecipientInfos().getRecipients();
            KeyTransRecipientInformation recipientInfo = (KeyTransRecipientInformation) recipientInfoCollection.iterator().next();
            JceKeyTransRecipient recipient = new JceKeyTransEnvelopedRecipient(decryptionKey);

            decryptedData = recipientInfo.getContent(recipient);
        }
        return decryptedData;
    }

    @Override
    public byte[] signData(byte[] data, final X509Certificate signingCertificate, final PrivateKey signingKey)
            throws CertificateEncodingException, CMSException, IOException, OperatorCreationException {
        byte[] signedMessage;
        List<X509Certificate> certList = new ArrayList<>();
        CMSTypedData cmsData = new CMSProcessableByteArray(data);
        certList.add(signingCertificate);
        JcaCertStore certs = new JcaCertStore(certList);
        CMSSignedDataGenerator cmsGenerator = new CMSSignedDataGenerator();
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA").build(signingKey);
        cmsGenerator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()).build(contentSigner, signingCertificate));
        cmsGenerator.addCertificates(certs);
        CMSSignedData cms = cmsGenerator.generate(cmsData, true);
        signedMessage = cms.getEncoded();
        return signedMessage;
    }

    @Override
    public boolean verifySignedData(final byte[] signedData)
            throws CMSException, IOException, OperatorCreationException, CertificateException {
        ByteArrayInputStream bIn = new ByteArrayInputStream(signedData);
        ASN1InputStream aIn = new ASN1InputStream(bIn);
        CMSSignedData s = new CMSSignedData(ContentInfo.getInstance(aIn.readObject()));
        aIn.close();
        bIn.close();
        Store<X509CertificateHolder> certs = s.getCertificates();
        SignerInformationStore signers = s.getSignerInfos();
        Collection<SignerInformation> c = signers.getSigners();
        SignerInformation signer = c.iterator().next();
        Collection<X509CertificateHolder> certCollection = certs.getMatches(signer.getSID());
        Iterator<X509CertificateHolder> certIt = certCollection.iterator();
        X509CertificateHolder certHolder = certIt.next();
        boolean verifyResult = signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(certHolder));
        if (!verifyResult) {
            return false;
        }
        return true;
    }
}
