/**********************************************************************************/
/* AuthEncryptor.java                                                             */
/* ------------------------------------------------------------------------------ */
/* DESCRIPTION: Performs authenticated encryption of data.                        */
/* ------------------------------------------------------------------------------ */
/* YOUR TASK: Implement authenticated encryption, ensuring:                       */
/*            (1) Confidentiality: the only way to recover encrypted data is to   */
/*                perform authenticated decryption with the same key and nonce    */
/*                used to encrypt the data.                                       */
/*            (2) Integrity: A party decrypting the data using the same key and   */
/*                nonce that were used to encrypt it can verify that the data has */
/*                not been modified since it was encrypted.                       */
/*                                                                                */
/**********************************************************************************/
public class AuthEncryptor {
    // Class constants.
    public static final int   KEY_SIZE_BYTES = StreamCipher.KEY_SIZE_BYTES;
    public static final int NONCE_SIZE_BYTES = StreamCipher.NONCE_SIZE_BYTES;

    // Instance variables.
    byte[] encKey;
    byte[] macKey;

    public AuthEncryptor(byte[] key) {
        assert key.length == KEY_SIZE_BYTES;

        // use a PRGen twice to make the keys
        PRGen prgen = new PRGen(key);

        encKey = new byte[32];
        prgen.nextBytes(encKey);

        macKey = new byte[32];
        prgen.nextBytes(macKey);
    }

    // Encrypts the contents of <in> so that its confidentiality and integrity are
    // protected against those who do not know the key and nonce.
    // If <nonceIncluded> is true, then the nonce is included in plaintext with the
    // output.
    // Returns a newly allocated byte[] containing the authenticated encryption of
    // the input.
    public byte[] encrypt(byte[] in, byte[] nonce, boolean includeNonce) {
        // padding is skipped during this encryption scheme - fair???

        // use the enc key to encrypt, along with the nonce
        StreamCipher strCiph = new StreamCipher(encKey, nonce, 0);
        byte[] encrypted = new byte[in.length];
        strCiph.cryptBytes(in, 0, encrypted, 0, in.length);

        // use the mac key to create a MAC
        PRF prf = new PRF(macKey);
        // advance the MAC as much as the nonce
        prf.update(nonce);
        // evaluate the PRF
        byte[] mac = prf.eval(encrypted);

        // concatenate the encrypted text and the cipher
        byte[] destination = new byte[encrypted.length + mac.length];
        System.arraycopy(encrypted, 0, destination, 0, encrypted.length);
        System.arraycopy(mac, 0, destination, encrypted.length, mac.length);

        // nonce is of fixed-size bytes (8), so simple concatenation should work
        if (includeNonce) {
            byte[] withNonce = new byte[destination.length + nonce.length];
            System.arraycopy(destination, 0, withNonce, 0, destination.length);
            System.arraycopy(nonce, 0, withNonce, destination.length, nonce.length);
            return withNonce;
        }

        return destination;
    }
}
