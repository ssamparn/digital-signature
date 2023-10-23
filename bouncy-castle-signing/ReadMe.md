# Digital Signature with Bouncy Castle

## Digital Signature is a technique for ensuring:

| What does Digital Signature ensures? | Explanation                                                          |                                
|--------------------------------------|----------------------------------------------------------------------|
| **Integrity**                        | **The message hasn’t been altered in transit**                           |
| **Authenticity**                     | **The author of the message is really who they claim to be**             |                       
| **Non-repudiation**                  | **The author of the message can’t later deny that they were the source** |                                       

**BouncyCastle is a Java library that complements the default Java Cryptographic Extension (JCE).**

### Sending a Message with a Digital Signature
Technically speaking, **a digital signature is the encrypted hash (digest, checksum) of a message**. That means we generate a hash from a message and encrypt it with a private key according to a chosen algorithm.

The message, the encrypted hash, the corresponding public key, and the algorithm are all then sent. This is classified as a message with its digital signature.

### Receiving and Checking a Digital Signature
To check the digital signature, the message receiver generates a new hash from the received message, decrypts the received encrypted hash using the public key, and compares them. If they match, the Digital Signature is said to be verified.

**We should note that we only encrypt the message hash, and not the message itself**. In other words, Digital Signature doesn't try to keep the message secret. Our digital signature only proves that the message was not altered in transit.

**When the signature is verified, we're sure that only the owner of the private key could be the author of the message.**

Please refer this [article](https://www.baeldung.com/java-digital-signature) and this [article](https://medium.com/@andredevlinux/generate-jks-encoded-base64-b9e3b4bb1b4d)

#### Create JKS:
```bash
$ keytool -genkeypair -alias message-signing -keyalg RSA -sigalg SHA256withRSA \
-keysize 2048 -validity 3650 -storetype JKS \
-keystore message-signing-keystore.jks -storepass password
```

#### Use the industry standard pkcs12 command to create keystore:
```bash
$ keytool -importkeystore -srckeystore message-signing-keystore.jks -destkeystore message-signing-keystore.jks -deststoretype pkcs12
```

#### Convert java keystore to base64 encoded string
```bash
$ openssl base64 -A -in message-signing-keystore.jks -out message-signing-keystore.b64
```

#### Retrieve / Export .cer file from java keystore
```bash
$ keytool -exportcert -keystore message-signing-keystore.jks -alias message-signing -file message-signing-public-certificate.cer
```