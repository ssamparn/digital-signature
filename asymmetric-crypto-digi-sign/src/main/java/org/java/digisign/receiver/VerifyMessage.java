package org.java.digisign.receiver;

import java.io.File;
import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;

public class VerifyMessage {

  private List<byte[]> list;

  public VerifyMessage(String filename, String publicKeyFile) throws Exception {
    ObjectInputStream in = new ObjectInputStream(new FileInputStream(filename));
    this.list = (List<byte[]>) in.readObject();
    in.close();

    System.out.println(verifySignature(list.get(0), list.get(1), publicKeyFile) ? "VERIFIED MESSAGE" +
        "\n----------------\n" + new String(list.get(0)) : "Could not verify the signature.");
  }

  //Method for signature verification that initializes with the Public Key,
  //updates the data to be verified and then verifies them using the signature
  private boolean verifySignature(byte[] data, byte[] signature, String keyFile) throws Exception {
    Signature sig = Signature.getInstance("SHA1withRSA");
    sig.initVerify(getPublic(keyFile));
    sig.update(data);

    return sig.verify(signature);
  }


  //Method to retrieve the Public Key from a file
  public PublicKey getPublic(String filename) throws Exception {
    byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
    X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    return keyFactory.generatePublic(spec);
  }

  public static void main(String[] args) throws Exception{
    new VerifyMessage("asymmetric-crypto-digi-sign/src/main/resources/SignedData.txt",
        "asymmetric-crypto-digi-sign/src/main/resources/public-key.txt");
  }

}
