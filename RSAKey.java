
import java.math.BigInteger;
import java.util.Arrays;

public class RSAKey {
    private BigInteger exponent;
    private BigInteger modulus;

    public RSAKey(BigInteger theExponent, BigInteger theModulus) {
        exponent = theExponent;
        modulus = theModulus;
    }

    public BigInteger getExponent() {
        return exponent;
    }

    public BigInteger getModulus() {
        return modulus;
    }

    /* Message Padding and OAEP Encoding
     * 
     * The next four methods are public to help us grade the assignment.
     * Implement these methods independent of each other, you should NOT call
     * addPadding/removePadding from within encodeOaep/decodeOaep (or vice-versa).
     * 
     * Encode an input:
     * 
     *     byte[] plaintext = 'Hello World'.getBytes();
     *     byte[] paddedPlaintext = addPadding(plaintext)
     *     byte[] paddedPlaintextOAEP = encodeOaep(paddedPlaintext, prgen);
     * 
     * Recover plaintext:
     * 
     *    byte[] unOAEP = decodeOaep(paddedPlaintextOAEP);
     *    byte[] recoveredPlaintext = removePadding(unOAEP);
     * 
     * In practice, these would be private methods and not part of the public API.
     */

    public byte[] encodeOaep(byte[] input, PRGen prgen) {
    	//if (input.length > maxPlaintextLength()) 
    	//	throw new IllegalArgumentException("Input exceeds maxPlaintextLength");

        // make a new 128-bit random value
        byte[] rand_num = new byte[16];
        prgen.nextBytes(rand_num);

        // seed a new PRGen with this random value padded with zeroes
        byte[] rand_pad = new byte[32];
        for (int m = 0; m < rand_num.length; m++) {
        	rand_pad[m] = rand_num[m];
        }

        PRGen G = new PRGen(rand_pad);

        // use G to generate an output of length (message + padding) (in bytes)
        // then XOR this value with the message + padding

        // pad the input message with 128 bits of zeroes
        byte[] input_pad = new byte[input.length + 16];
        for (int p = 0; p < input.length; p++) {
        	input_pad[p] = input[p];
        }

        //byte[] input_pad = input;

        // length of the message + padding
        int len = input_pad.length;

		byte[] in_hash = new byte[len];

		int i = 0;
		byte[] outG = new byte[len];
		G.nextBytes(outG);
		for (byte b : outG)
		    in_hash[i] = (byte)(b ^ input_pad[i++]);

        // seeds H with a public key (will use 0 here)
        byte[] zero = new byte[1];
        PRF prf = new PRF(zero);
        // returns 256-bit output
        byte[] prf_output = prf.eval(in_hash);

        // truncate the hash to 128 bits by taking first 128 bits
        byte[] out_hash = new byte[16];
        for (int k = 0; k < 16; k++) {
        	out_hash[k] = prf_output[k];
        }

        // (out_hash XOR rand_num)
        // should STILL be 128 bits!
		byte[] outXrand = new byte[16];

		int j = 0;
		for (byte b : rand_num)
		    outXrand[j] = (byte)(b ^ out_hash[j++]);

        // append in_hash and (out_hash XOR random num)
		byte[] destination = new byte[outXrand.length + in_hash.length];
		// copy in_hash into start of destination 
		System.arraycopy(in_hash, 0, destination, 0, in_hash.length);
		// copy (out_hash XOR rand_num) into end of destination
		System.arraycopy(outXrand, 0, destination, in_hash.length, outXrand.length);

		//System.out.print("Output from encode ");
    	//System.out.println(Arrays.toString(destination));
    	//System.out.println();

		// return result; 
		return destination;
     }
     
    public byte[] decodeOaep(byte[] input) {

        //System.out.print("Input into decode ");
    	//System.out.println(Arrays.toString(input));
    	//System.out.println();

        // split the input into two portions

    	int len = input.length;

        // bit length of right portion
        int r_len = 16;

        // the left is (message + pad) XOR (G(r))
        // the right is (hash output, truncated) XOR r (must be 128 bits)
        byte[] left = new byte[len - r_len];
        byte[] right = new byte[r_len];

        // copies items into their respective arrays
        for (int i = 0; i < len - r_len; i++) {
        	left[i] = input[i];
        }
        for (int j = 0; j < r_len; j++) {
        	right[j] = input[j + len - r_len];
        }

        // the same PRF is created with the public key
        byte[] zero = new byte[1];
        PRF prf = new PRF(zero);

        // use left side to seed the PRF (H)
        byte[] prf_output = prf.eval(left);

        // as in encode, only take the first half
        byte[] out_hash = new byte[16];
        for (int i = 0; i < 16; i++) {
        	out_hash[i] = prf_output[i];
        }

        // XOR out_hash with the right-side array (derived fr. rand)
        byte[] r_prime = new byte[r_len];

		int i = 0;
		for (byte b : right)
		    r_prime[i] = (byte)(b ^ out_hash[i++]);

		// r_prime is 128 bits. Must pad with zeroes again!
		byte[] rp_pad = new byte[32];
        for (int m = 0; m < r_prime.length; m++) {
        	rp_pad[m] = r_prime[m];
        }

		// r_prime (presumably, the same random number we used to 
		// seed G during encoding) is then used to seed a PRGen
		PRGen G = new PRGen(rp_pad);

		// a 128-bit output from this PRGen is then XORed with left
		byte[] message_pad = new byte[len - r_len];

		int j = 0;
		byte[] outG = new byte[len - r_len];
		G.nextBytes(outG);
		for (byte b : outG)
		    message_pad[j] = (byte)(b ^ left[j++]);

		// check that the last 16 bytes are zeroes
		
		for (int l = message_pad.length - 1; l < message_pad.length - 1 - 16; l--) {
			//System.out.println("checking..." + l);
			if (message_pad[l] != (byte)(0)) {
				//System.out.println("returns null");
				return null;
			}
		}
		
		
		// this should yield the original message + pad
		return Arrays.copyOfRange(message_pad, 0, message_pad.length - 16);
    }
     
    public byte[] addPadding(byte[] input) {
        int max = maxPlaintextLength() + 1;
        int len = input.length;

        if (len > maxPlaintextLength()) 
    		throw new IllegalArgumentException("Input exceeds maxPlaintextLength");

        // pad the input with zeroes until 128 bits
    	byte[] padded = new byte[max];

    	// copies in the message
        for (int i = 0; i < len; i++) {
        	padded[i] = input[i];
        }
        // append the byte 1000000 (the one serves as a marker for the appended 0s)
        padded[len] = (byte)(-128);

        // fill the rest with zeroes
        for (int i = len + 1; i < max; i++) {
        	padded[i] = (byte)(0);
        }

        return padded;
    }
    
    public byte[] removePadding(byte[] input) {
        int padIdx = input.length - 1;

        while (input[padIdx] != (byte)(-128) && input[padIdx] == (byte)(0)) {
        	padIdx--;
        }

        return Arrays.copyOfRange(input, 0, padIdx);
    }
    
    public int maxPlaintextLength() {
        // Return the largest N such that any plaintext of size N bytes
        //      can be encrypted with this key and padding/encoding.

    	// N - (1 for overflow) - b0 - b1 - 8 (at least one byte of pad)
        return (modulus.bitLength() - 1 - 256 - 8) / 8;
    }
    
    /*
     * RSA Operations
     */
    
    // RSA((e,N),x) = x^e mod N
    // Bigger function
    public byte[] encrypt(byte[] plaintext, PRGen prgen) {
        if (plaintext == null)    throw new NullPointerException();
        
        // check validity of input
        int len = plaintext.length;
        if (len > maxPlaintextLength()) 
        	throw new IllegalArgumentException("Input exceeds maxPlaintextLength");

        // add padding
        byte[] txt_pad = addPadding(plaintext);

        // call OAEP encoding
        byte[] enc_arr = encodeOaep(txt_pad, prgen);

        // turn result into a big integer
        BigInteger enc_big = HW2Util.bytesToBigInteger(enc_arr);

        // perform RSA encryption, if this is the public key
        BigInteger encrypted = enc_big.modPow(exponent, modulus);

        // convert this BigInteger back to a byte[] and return it

        // HOW DO I FIX THIS
        byte[] result = encrypted.toByteArray();

        return result;
    }

    public byte[] decrypt(byte[] ciphertext) {
        if (ciphertext == null)    throw new NullPointerException();
    
        // convert the ciphertext to a BigInteger
        BigInteger ciph_big = HW2Util.bytesToBigInteger(ciphertext);

        // perform RSA decryption, if this is the private key
        BigInteger decrypted = ciph_big.modPow(exponent, modulus);

        // convert back to a byte array

        // SAME; HOW DO I DETERMINE THE LENGTH
		byte[] dec_arr = HW2Util.bigIntegerToBytes(decrypted, maxPlaintextLength() + 1 + 32);

        // decode the OAEP encoding, remove the padding, return this result
        byte[] decoded = decodeOaep(dec_arr);

        return removePadding(decoded);
    }

    public byte[] sign(byte[] message, PRGen prgen) {
        // Create a digital signature on <message>. The signature need
        //     not contain the contents of <message>--we will assume
        //     that a party who wants to verify the signature will already
        //     know which message this is (supposed to be) a signature on.
        if (message == null)    throw new NullPointerException();

        // hash the message
        byte[] zero = new byte[1];
        PRF prf = new PRF(zero);

        byte[] hashed = prf.eval(message);

        return encrypt(hashed, prgen);
    }

    public boolean verifySignature(byte[] message, byte[] signature) {
        // Verify a digital signature. Returns true if  <signature> is
        //     a valid signature on <message>; returns false otherwise.
        //     A "valid" signature is one that was created by calling
        //     <sign> with the same message, using the other RSAKey that
        //     belongs to the same RSAKeyPair as this object.
        if ((message == null) || (signature == null))    throw new NullPointerException();

        byte[] decrypted = decrypt(signature);

        // create the same PRF, hash your message
        byte[] zero = new byte[1];
        PRF prf = new PRF(zero);

        byte[] hashed = prf.eval(message);

        // compare hashed and decrypted to see if they are the same
        return Arrays.equals(hashed, decrypted);
    }

    public static void main(String[] args) {
    	//byte[] input = {0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1};
    	byte[] input = {1, 2, 3, 4, 5, 6, 7, 0, 9, 10, 5, 12, 13, 14, 15, 10};
    	// arbitrary all-zero seed
    	byte[] seed = new byte[32];
    	
    	// arbitrary modulus and exponent
    	PRGen prgen = new PRGen(seed);

    	// RSA decrypt doesn't work at 1024?
    	RSAKeyPair keyPair = new RSAKeyPair(prgen, 1024);
    	RSAKey pub_key = keyPair.getPublicKey();
    	RSAKey prv_key = keyPair.getPrivateKey();

    	
    	System.out.print("Input: ");
    	System.out.println(Arrays.toString(input));
    	System.out.println();

    	byte[] input_pad = pub_key.addPadding(input);
    	System.out.print("Input (Padded): ");
    	System.out.println(Arrays.toString(input_pad));
    	System.out.println();

    	byte[] encoded = pub_key.encodeOaep(input_pad, prgen);
    	System.out.print("Encoded: ");
    	System.out.println(Arrays.toString(encoded));
    	System.out.println();

    	byte[] decoded = pub_key.decodeOaep(encoded);
    	System.out.print("Decoded: ");
    	System.out.println(Arrays.toString(decoded));
    	System.out.println();

    	byte[] dec_nopad = pub_key.removePadding(decoded);
    	System.out.print("Decoded (No pad): ");
    	System.out.println(Arrays.toString(dec_nopad));
    	System.out.println();

		
    	byte[] rsa_encrypted = pub_key.encrypt(input, prgen);
    	System.out.print("RSA Encrypted: ");
    	System.out.println(Arrays.toString(rsa_encrypted));
    	System.out.println();

    	byte[] rsa_decrypted = prv_key.decrypt(rsa_encrypted);
    	System.out.print("RSA Decrypted: ");
    	System.out.println(Arrays.toString(rsa_decrypted));
    	System.out.println();
    	

    	//byte[] seed2 = new byte[32];
    	//for (int i = 0; i < 32; i++) seed2[i] = (byte)(1);
    	//PRGen prgen2 = new PRGen(seed2);
	
		// RETURNS TRUE ONLY WHEN I COMMENT OUT PREVIOUS TESTS????

    	byte[] signed = prv_key.sign(input, prgen);	
    	System.out.print("Signature: ");
    	System.out.println(Arrays.toString(signed));
    	System.out.println();

    	System.out.println("Verify signature: ");

    	if (pub_key.verifySignature(input, signed)) System.out.println("True");
    	else System.out.println("False");
    	System.out.println();


    }
}
