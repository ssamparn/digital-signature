package org.bouncycastle.digisign.bouncycastlesigning.config;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.commons.codec.binary.Base64InputStream;
import org.bouncycastle.digisign.bouncycastlesigning.properties.DigiSignProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class DigiSignConfig {

    private final DigiSignProperties digiSignProperties;

    @Bean
    public KeyStore loadKeyStore() {
        log.info("loading keystore");

        return createKeyStoreFromBase64EncodedString(digiSignProperties.getKeyStore(), digiSignProperties.getKeyStorePassword(),
                digiSignProperties.getKeyStoreType());
    }

    private KeyStore createKeyStoreFromBase64EncodedString(String base64EncodedKeyStore, String keyStorePassword, String keyStoreType) {
        try (InputStream inputStream = new ByteArrayInputStream(base64EncodedKeyStore.getBytes(StandardCharsets.UTF_8));
             Base64InputStream keystoreInputStream = new Base64InputStream(inputStream)) {

            KeyStore keystore = KeyStore.getInstance(keyStoreType);
            keystore.load(keystoreInputStream, keyStorePassword.toCharArray());

            return keystore;
        } catch (GeneralSecurityException | IOException e) {
            throw new RuntimeException("Failed to load keystore/truststore ", e);
        }
    }

    @Bean
    public PrivateKey loadPrivateKey(KeyStore keyStore) {
        try {
            Key key = keyStore.getKey(digiSignProperties.getAlias(), digiSignProperties.getPrivateKeyPassword().toCharArray());
            if (key instanceof PrivateKey) {
                return (PrivateKey) key;
            }
            throw new RuntimeException("Key stored under alias " + digiSignProperties.getAlias() + " is not a private key, but: " + key);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            throw new RuntimeException("Failed to load private key under alias " + digiSignProperties.getAlias(), e);
        }
    }

    @Bean
    public PublicKey loadPublicKey(KeyStore keyStore) {
        try {
            Certificate certificate = keyStore.getCertificate(digiSignProperties.getAlias());

            if (null == certificate) {
                throw new RuntimeException("There is no X.509 certificate under alias " + digiSignProperties.getAlias());
            }

            if (null != certificate.getPublicKey()) {
                return certificate.getPublicKey();
//      return Base64.encodeBase64String(certificate.getPublicKey().getEncoded()) if we want public key in a base64 encoded string format
            }
            throw new RuntimeException("Public key under alias " + digiSignProperties.getAlias() + " is not a public key");
        } catch (KeyStoreException e) {
            throw new RuntimeException("Failed to load public key under alias " + digiSignProperties.getAlias(), e);
        }
    }

    @Bean
    public X509Certificate loadCertificate(KeyStore keyStore) {
        try {
            Certificate certificate = keyStore.getCertificate(digiSignProperties.getAlias());
            if (null == certificate) {
                throw new RuntimeException("There is no X.509 certificate under alias " + digiSignProperties.getAlias());
            }
            if (certificate instanceof X509Certificate) {
                return (X509Certificate) certificate;
            }
            throw new RuntimeException("Certificate under alias " + digiSignProperties.getAlias() + " is not an X.509 certificate, but: " + certificate);
        } catch (KeyStoreException e) {
            throw new RuntimeException("Failed to load certificate under alias " + digiSignProperties.getAlias(), e);
        }
    }

    @Bean
    public List<X509Certificate> loadCertificateChain(KeyStore keyStore) {
        try {
            Certificate[] certificates = keyStore.getCertificateChain(digiSignProperties.getAlias());

            if (null == certificates) {
                throw new RuntimeException("There is no X.509 certificate chain under alias " + digiSignProperties.getAlias());
            }

            return Stream.of(certificates).map(certificate -> (X509Certificate) certificate).collect(Collectors.toList());
        } catch (KeyStoreException e) {
            throw new RuntimeException("Failed to load certificate under alias " + digiSignProperties.getAlias(), e);
        }
    }

    @Bean
    public List<X509Certificate> loadCertificates(KeyStore keyStore) {
        List<X509Certificate> certificates = new LinkedList<>();
        try {
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (keyStore.isCertificateEntry(alias)) {
                    X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
                    certificates.add(certificate);

                    log.info("Added certificate under alias: " + alias + " for " + certificate.getSubjectDN() + " to list of certificates");
                }
            }
        } catch (KeyStoreException e) {
            throw new RuntimeException("Failed to load certificates from keystore: " + keyStore);
        }
        return certificates;
    }
}
