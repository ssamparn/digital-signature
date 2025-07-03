package org.java.digisign.keypair;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class GenerateKeyPairs {

    private KeyPairGenerator keyPairGen;
    private KeyPair keyPair;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    public GenerateKeyPairs(int keyLength) throws NoSuchAlgorithmException {
        this.keyPairGen = KeyPairGenerator.getInstance("RSA");
        this.keyPairGen.initialize(keyLength);
    }

    public void createKeys() {
        this.keyPair = this.keyPairGen.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    public PrivateKey getPrivateKey() {
        return this.privateKey;
    }

    public PublicKey getPublicKey() {
        return this.publicKey;
    }

    public void writeToFile(String path, byte[] bytes) throws IOException {
        File file = new File(path);
        file.getAbsolutePath();

        FileOutputStream fos = new FileOutputStream(file);
        fos.write(bytes);
        fos.flush();
        fos.close();
    }

    public static void main(String[] args) {
        GenerateKeyPairs generateKeyPairs;
        try {
            generateKeyPairs = new GenerateKeyPairs(2048);
            generateKeyPairs.createKeys();
            generateKeyPairs.writeToFile("asymmetric-crypto-digi-sign/src/main/resources/asymmetric/public-key.txt",
                    generateKeyPairs.getPublicKey().getEncoded());
            generateKeyPairs.writeToFile("asymmetric-crypto-digi-sign/src/main/resources/asymmetric/private-key.txt",
                    generateKeyPairs.getPrivateKey().getEncoded());
        } catch (NoSuchAlgorithmException | IOException e) {
            System.err.println(e.getMessage());
        }
    }
}
