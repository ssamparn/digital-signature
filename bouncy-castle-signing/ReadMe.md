# Digital Signature with Bouncy Castle

## Digital Signature is a technique for ensuring:

BouncyCastle is a Java library that complements the default Java Cryptographic Extension (JCE).

### Sending a Message with a Digital Signature
Technically speaking, **a digital signature is the encrypted hash (digest, checksum) of a message**. That means we generate a hash from a message and encrypt it with a private key according to a chosen algorithm.

The message, the encrypted hash, the corresponding public key, and the algorithm are all then sent. This is classified as a message with its digital signature.

### Receiving and Checking a Digital Signature
To check the digital signature, the message receiver generates a new hash from the received message, decrypts the received encrypted hash using the public key, and compares them. If they match, the Digital Signature is said to be verified.

**We should note that we only encrypt the message hash, and not the message itself**. In other words, Digital Signature doesn't try to keep the message secret. Our digital signature only proves that the message was not altered in transit.

**When the signature is verified, we're sure that only the owner of the private key could be the author of the message.**

Please [refer](https://www.baeldung.com/java-digital-signature)