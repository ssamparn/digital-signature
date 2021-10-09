package org.bouncycastle.digisign.bouncycastlesigning;

import java.security.NoSuchAlgorithmException;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class BouncyCastleSigningApplication {

	public static void main(String[] args) {
		SpringApplication.run(BouncyCastleSigningApplication.class, args);
	}

//	check if the crypto.policy is set to unlimited
//	public static void main(String[] args) throws NoSuchAlgorithmException {
//		int maxKeySize = javax.crypto.Cipher.getMaxAllowedKeyLength("AES");
//		System.out.println("Max Key Size for AES : " + maxKeySize);
//	}

}
