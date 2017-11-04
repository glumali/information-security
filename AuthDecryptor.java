/**********************************************************************************/
/* AuthDecrytor.java                                                              */
/* ------------------------------------------------------------------------------ */
/* DESCRIPTION: Performs authenticated decryption of data encrypted using         */
/*              AuthEncryptor.java.                                               */
/* ------------------------------------------------------------------------------ */
/* YOUR TASK: Decrypt data encrypted by your implementation of AuthEncryptor.java */
/*            if provided with the appropriate key and nonce.  If the data has    */
/*            been tampered with, return null.                                    */
/*                                                                                */
/**********************************************************************************/
import java.util.Arrays;

public class AuthDecryptor {
    // Class constants.
    public static final int   KEY_SIZE_BYTES = AuthEncryptor.KEY_SIZE_BYTES;
    public static final int NONCE_SIZE_BYTES = AuthEncryptor.NONCE_SIZE_BYTES;

    // Instance variables.
    byte[] encKey;
    byte[] macKey;

    public AuthDecryptor(byte[] key) {
        assert key.length == KEY_SIZE_BYTES;
        
        PRGen prgen = new PRGen(key);

        encKey = new byte[32];
        prgen.nextBytes(encKey);

        macKey = new byte[32];
        prgen.nextBytes(macKey);
    }

    // Decrypts and authenticates the contents of <in>.  <in> should have been encrypted
    // using your implementation of AuthEncryptor.
    // The nonce has been included in <in>.
    // If the integrity of <in> cannot be verified, then returns null.  Otherwise,
    // returns a newly allocated byte[] containing the plaintext value that was
    // originally encrypted.
    public byte[] decrypt(byte[] in) {
        // byte length of the input
        int len = in.length;
        // byte length of the nonce
        int n_len = 8;
        // byte length of cipher portion
        int c_len = 32;

        // input structure: enc (variable length), cipher (32-byte), nonce (8-byte)
        byte[] encrypted = new byte[len - c_len - n_len];
        byte[] cipher = new byte[c_len];
        byte[] nonce = new byte[n_len];

        // copies items into their respective arrays
        // (CHECK THIS)

        for (int i = 0; i < len - c_len - n_len; i++) {
            encrypted[i] = in[i];
        }
        for (int j = 0; j < c_len; j++) {
            cipher[j] = in[j + len - c_len - n_len];
        }
        for (int k = 0; k < n_len; k++) {
            nonce[k] = in[k + len - n_len];
        }

        // recreate the mac with the encrypted message side
        PRF prf = new PRF(macKey);
        // advance the MAC as much as the nonce
        prf.update(nonce);
        // evaluate the PRF
        byte[] mac = prf.eval(encrypted);

        // check that your computed mac and your cipher are the same
        // if not, must have been tampered with; return null
        if (!(Arrays.equals(mac, cipher))) {
            return null;
        }

        // calling cryptByte on the encrypted bytes should decrypt it
        // use the enc key to encrypt, along with the nonce
        StreamCipher strCiph = new StreamCipher(encKey, nonce, 0);
        byte[] result = new byte[encrypted.length];
        strCiph.cryptBytes(encrypted, 0, result, 0, encrypted.length);

        // return the result
        return result;
    }

    // Decrypts and authenticates the contents of <in>.  <in> should have been encrypted
    // using your implementation of AuthEncryptor.
    // The nonce used to encrypt the data is provided in <nonce>.
    // If the integrity of <in> cannot be verified, then returns null.  Otherwise,
    // returns a newly allocated byte[] containing the plaintext value that was
    // originally encrypted.
    public byte[] decrypt(byte[] in, byte[] nonce) {
        assert nonce != null && nonce.length == NONCE_SIZE_BYTES;
        
        // byte length of the input
        int len = in.length;
        // byte length of cipher portion
        int c_len = 32;

        // input structure: left side (variable length), right side (32-byte)
        byte[] encrypted = new byte[len - c_len];
        byte[] cipher = new byte[c_len];

        // copies items into their respective arrays
        for (int i = 0; i < len - c_len; i++) {
            encrypted[i] = in[i];
        }
        for (int j = 0; j < c_len; j++) {
            cipher[j] = in[j + len - c_len];
        }

        // recreate the mac with the encrypted message side
        PRF prf = new PRF(macKey);
        // advance the MAC as much as the nonce
        prf.update(nonce);
        // evaluate the PRF
        byte[] mac = prf.eval(encrypted);

        // check that your computed mac and your cipher are the same
        // if not, must have been tampered with; return null
        if (!(Arrays.equals(mac, cipher))) {
            return null;
        }

        // calling cryptByte on the encrypted bytes should decrypt it
        // use the enc key to encrypt, along with the nonce
        StreamCipher strCiph = new StreamCipher(encKey, nonce, 0);
        byte[] result = new byte[encrypted.length];
        strCiph.cryptBytes(encrypted, 0, result, 0, encrypted.length);

        // return the result
        return result;
    }
}
