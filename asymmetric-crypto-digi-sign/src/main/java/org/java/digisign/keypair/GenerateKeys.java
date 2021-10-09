package org.java.digisign.keypair;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class GenerateKeys {

  private KeyPairGenerator keyPairGen;
  private KeyPair keyPair;
  private PrivateKey privateKey;
  private PublicKey publicKey;

  public GenerateKeys(int keyLength) throws NoSuchAlgorithmException {
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
    GenerateKeys generateKeys;
    try {
      generateKeys = new GenerateKeys(1024);
      generateKeys.createKeys();
      generateKeys.writeToFile("asymmetric-crypto-digi-sign/src/main/resources/public-key.txt", generateKeys.getPublicKey().getEncoded());
      generateKeys.writeToFile("asymmetric-crypto-digi-sign/src/main/resources/private-key.txt", generateKeys.getPrivateKey().getEncoded());
    } catch (NoSuchAlgorithmException | IOException e) {
      System.err.println(e.getMessage());
    }
  }
}
