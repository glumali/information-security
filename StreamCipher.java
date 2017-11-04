/**********************************************************************************/
/* StreamCipher.java                                                              */
/* ------------------------------------------------------------------------------ */
/* DESCRIPTION: This class implements a stream cipher, which encrypts or decrypts */
/*              a stream of bytes (the two operations are identical).             */
/* ------------------------------------------------------------------------------ */
/* YOUR TASK: Implement a stream cipher.                                          */
/* ------------------------------------------------------------------------------ */
/* USAGE: Create a new StreamCipher with key k of length <KEY_SIZE_BYTES> and     */
/*        nonce n of length NONCE_SIZE_BYTES:                                     */
/*            StreamCipher enc = new StreamCipher(k, n);                          */
/*                                                                                */
/*        Encrypt two bytes b1 and b2:                                            */
/*            byte e1 = enc.cryptByte(b1);                                        */
/*            byte e2 = enc.cryptByte(b2);                                        */
/*                                                                                */
/*        Decrypt two bytes e1 and e2.  First, create a StreamCipher with the     */
/*        same key and nonce, and then call cryptByte() on the encrypted bytes in */
/*        the same order.                                                         */
/*            StreamCipher dec = new StreamCipher(k, n);                          */
/*            byte d1 = dec.cryptByte(e1);                                        */
/*            byte d2 = dec.cryptByte(e2);                                        */
/*            assert (d1 == b1 && d2 == b2);                                      */
/**********************************************************************************/
public class StreamCipher {
    // Class constants.
    public static final int KEY_SIZE_BYTES   = PRGen.KEY_SIZE_BYTES;
    public static final int NONCE_SIZE_BYTES = 8;

    // Instance variables.
    private byte[] key;
    private byte[] nonce;
    private PRF prf;
    private PRGen gen;

    // Creates a new StreamCipher with key <key> and nonce composed of
    // nonceArr[nonceOffset] through nonceArr[nonceOffset + NONCE_SIZE_BYTES - 1].
    public StreamCipher(byte[] key, byte[] nonceArr, int nonceOffset) {
        assert key.length == KEY_SIZE_BYTES;

        // copy in key
        this.key = new byte[KEY_SIZE_BYTES];
        for(int i = 0; i < KEY_SIZE_BYTES; i++) this.key[i] = key[i];

        // copy in nonce
        nonce = new byte[NONCE_SIZE_BYTES];
        for(int i = nonceOffset; i < nonceOffset + NONCE_SIZE_BYTES; i++)
            nonce[i - nonceOffset] = nonceArr[i];

        // initialize Fk
        prf = new PRF(key);

        // create seed
        byte[] seed = prf.eval(nonce);

        // seed the PRGen
        gen = new PRGen(seed);
    }

    public StreamCipher(byte[] key, byte[] nonce) {
        this(key, nonce, 0); // Call the other constructor.
    }

    // Encrypts or decrypts the next byte in the stream.
    public byte cryptByte(byte in) {
        // encrypts by XOR with output of the generator
        int rand = gen.next(8);
        return (byte)(in ^ (byte) rand);
    }

    // Encrypts or decrypts multiple bytes.
    // Encrypts or decrypts inBuf[inOffset] through inBuf[inOffset + numBytes - 1],
    // storing the result in outBuf[outOffset] through outBuf[outOffset + numBytes - 1].
    public void cryptBytes(byte[]  inBuf, int  inOffset, 
                           byte[] outBuf, int outOffset, int numBytes) {
        for (int i = 0; i < numBytes; i++) {
            outBuf[i + outOffset] = cryptByte(inBuf[i + inOffset]);
        }
    }

    // for testing
    public static void main(String[] args) {
        byte[] key = new byte[32];
        byte[] nonArr = new byte[128];
        byte[] text = {1, 0, 0, 0, 1, 0, 1, 0};

        StreamCipher strcph = new StreamCipher(key, nonArr, 5);

        System.out.print("Original bytes: ");
        for (int i = 0; i < text.length; i++) {
            System.out.print(text[i] + " ");
        }
        System.out.println();

        int offset = 3;
        byte[] result = new byte[5];
        strcph.cryptBytes(text, offset, result, 0, 5);

        System.out.print("Encrypted bytes starting from " + offset + " : ");
        for (int i = 0; i < result.length; i++) {
            System.out.print(result[i] + " ");
        }
        System.out.println();
    }
}
