package org.java.digisign.asymmetric;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.binary.Base64;

public class AsymmetricCryptography {

  private Cipher cipher;

  public AsymmetricCryptography() throws NoSuchPaddingException, NoSuchAlgorithmException {
    this.cipher = Cipher.getInstance("RSA");
  }

  public PrivateKey getPrivateKey(String fileName) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
    byte[] privateKeyBytes = Files.readAllBytes(Paths.get(new File(fileName).getAbsolutePath()));
    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKeyBytes);
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    return keyFactory.generatePrivate(spec);
  }

  public PublicKey getPublicKey(String fileName) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
    byte[] publicKeyBytes = Files.readAllBytes(Paths.get(new File(fileName).getAbsolutePath()));
    X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKeyBytes);
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    return keyFactory.generatePublic(spec);
  }

  public void encryptFile(byte[] input, File output, PrivateKey privateKey) throws IOException, GeneralSecurityException {
    this.cipher.init(Cipher.ENCRYPT_MODE, privateKey);
    writeToFile(output, this.cipher.doFinal(input));
  }

  public void decryptFile(byte[] input, File output, PublicKey publicKey) throws IOException, GeneralSecurityException {
    this.cipher.init(Cipher.DECRYPT_MODE, publicKey);
    writeToFile(output, this.cipher.doFinal(input));
  }

  private void writeToFile(File output, byte[] toWrite) throws IOException {
    FileOutputStream fos = new FileOutputStream(output);
    fos.write(toWrite);
    fos.flush();
    fos.close();
  }

  public String encryptText(String msg, PrivateKey privateKey)
      throws UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
    this.cipher.init(Cipher.ENCRYPT_MODE, privateKey);
    return Base64.encodeBase64String(cipher.doFinal(msg.getBytes("UTF-8")));
  }

  public String decryptText(String msg, PublicKey publicKey)
      throws InvalidKeyException, UnsupportedEncodingException,
      IllegalBlockSizeException, BadPaddingException {
    this.cipher.init(Cipher.DECRYPT_MODE, publicKey);
    return new String(cipher.doFinal(Base64.decodeBase64(msg)), "UTF-8");
  }

  public byte[] getFileInBytes(File f) throws IOException {
    FileInputStream fis = new FileInputStream(f);
    byte[] fbytes = new byte[(int) f.length()];
    fis.read(fbytes);
    fis.close();
    return fbytes;
  }

  public static void main(String[] args) throws Exception {
    AsymmetricCryptography asymmetricCryptography = new AsymmetricCryptography();

    PrivateKey privateKey = asymmetricCryptography.getPrivateKey("asymmetric-crypto-digi-sign/src/main/resources/asymmetric/private-key"
        + ".txt");
    PublicKey publicKey = asymmetricCryptography.getPublicKey("asymmetric-crypto-digi-sign/src/main/resources/asymmetric/public-key.txt");

    // String Encryption and Decryption
    String message = "Cryptography is fun!";
    String encrypted_msg = asymmetricCryptography.encryptText(message, privateKey);
    String decrypted_msg = asymmetricCryptography.decryptText(encrypted_msg, publicKey);

    System.out.println("Original Message: " + message +
        "\nEncrypted Message: " + encrypted_msg
        + "\nDecrypted Message: " + decrypted_msg);

    // File Encryption and Decryption
    if (new File("asymmetric-crypto-digi-sign/src/main/resources/text.txt").exists()) {
      asymmetricCryptography.encryptFile(asymmetricCryptography.getFileInBytes(new File("asymmetric-crypto-digi-sign/src/main/resources/text.txt")),
          new File("asymmetric-crypto-digi-sign/src/main/resources/text_encrypted.txt"), privateKey);
      asymmetricCryptography.decryptFile(asymmetricCryptography.getFileInBytes(new File("asymmetric-crypto-digi-sign/src/main/resources/text_encrypted.txt")),
          new File("asymmetric-crypto-digi-sign/src/main/resources/text_decrypted.txt"), publicKey);
    } else {
      System.out.println("Create a file text.txt under folder KeyPair");
    }
  }
}
