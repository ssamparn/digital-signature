package org.java.digisign.sender;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JOptionPane;

public class SigningMessage {

    private List<byte[]> list;

    //The constructor of Message class builds the list that will be written to the file.
    //The list consists of the message and the signature.
    public SigningMessage(String data, String keyFile) throws InvalidKeyException, Exception {
        list = new ArrayList<>();
        list.add(data.getBytes());
        list.add(sign(data, keyFile));
    }

    //The method that signs the data using the private key that is stored in keyFile path
    private byte[] sign(String data, String keyFile)
            throws Exception {
        Signature rsa = Signature.getInstance("SHA1withRSA");
        rsa.initSign(getPrivateKey(keyFile));
        rsa.update(data.getBytes());

        return rsa.sign();
    }

    //Method to retrieve the Private Key from a file
    public PrivateKey getPrivateKey(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(spec);
    }

    //Method to write the List of byte[] to a file
    private void writeToFile(String filename) throws IOException {
        File file = new File(filename);
        file.getAbsolutePath();

        ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(filename));
        out.writeObject(list);
        out.close();
        System.out.println("Your file is ready.");
    }


    public static void main(String[] args) throws Exception {
        String messageToBeSigned = JOptionPane.showInputDialog("Type your message here to sign");

        new SigningMessage(messageToBeSigned, "asymmetric-crypto-digi-sign/src/main/resources/asymmetric/private-key.txt").writeToFile(
                "asymmetric-crypto-digi-sign/src/main/resources/SignedData.txt");
    }

}
