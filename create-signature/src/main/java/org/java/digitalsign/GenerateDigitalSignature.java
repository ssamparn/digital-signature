package org.java.digitalsign;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;

public class GenerateDigitalSignature {

    public static void main(String[] args) {
        try {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DSA", "SUN");
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");

            keyPairGen.initialize(1024, random);
            KeyPair keyPair = keyPairGen.generateKeyPair();

            // Get a PrivateKey from the generated key pair.
            PrivateKey privateKey = keyPair.getPrivate();

            // Get an instance of Signature object and initialize it.
            Signature signature = Signature.getInstance("SHA1withDSA", "SUN");
            signature.initSign(privateKey);

            // Supply the data to be signed to the Signature object
            // using the update() method and generate the digital
            // signature.
            byte[] bytes = Files.readAllBytes(Paths.get(new File("create-signature/src/main/resources/file.txt").getAbsolutePath()));
            signature.update(bytes);
            byte[] digitalSignature = signature.sign();

            // Save digital signature and the public key to a file.
            Files.write(Paths.get(new File("create-signature/src/main/resources/signature.txt").getAbsolutePath()), digitalSignature);
            Files.write(Paths.get(new File("create-signature/src/main/resources/public-key.txt").getAbsolutePath()),
                    keyPair.getPublic().getEncoded());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
