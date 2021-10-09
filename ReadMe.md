# Digital Signature

## Digital Signature is a technique for ensuring:

**1. Integrity:** The message hasn't been altered in transit.\
**2. Authenticity:** The author of the message is really who they claim to be.\
**3. Non-repudiation:** The author of the message can't later deny that they were the source.

### Sending a Message with a Digital Signature
Technically speaking, **a digital signature is the encrypted hash (digest, checksum) of a message**. That means we generate a hash from a message and encrypt it with a private key according to a chosen algorithm.

The message, the encrypted hash, the corresponding public key, and the algorithm are all then sent. This is classified as a message with its digital signature.

### Receiving and Checking a Digital Signature
To check the digital signature, the message receiver generates a new hash from the received message, decrypts the received encrypted hash using the public key, and compares them. If they match, the Digital Signature is said to be verified.

**We should note that we only encrypt the message hash, and not the message itself**. In other words, Digital Signature doesn't try to keep the message secret. Our digital signature only proves that the message was not altered in transit.

**When the signature is verified, we're sure that only the owner of the private key could be the author of the message.**

Please [refer](https://www.baeldung.com/java-digital-signature)