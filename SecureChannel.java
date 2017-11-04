
import java.io.InputStream;
import java.io.OutputStream;

import java.io.IOException;

import java.nio.ByteBuffer;

import java.util.Arrays;

public class SecureChannel extends InsecureChannel {
    // This is just like an InsecureChannel, except that it provides 
    //    authenticated encryption for the messages that pass
    //    over the channel.   It also guarantees that messages are delivered 
    //    on the receiving end in the same order they were sent (returning
    //    null otherwise).  Also, when the channel is first set up,
    //    the client authenticates the server's identity, and the necessary
    //    steps are taken to detect any man-in-the-middle (and to close the
    //    connection if a MITM is detected).
    //
    // The code provided here is not secure --- all it does is pass through
    //    calls to the underlying InsecureChannel.

    byte[] sharedKey;
    // nonce counter
    long nonce_l;

    public SecureChannel(InputStream inStr, OutputStream outStr, 
            PRGen rand, boolean iAmServer,
            RSAKey serverKey) throws IOException {
        // if iAmServer==false, then serverKey is the server's *public* key
        // if iAmServer==true, then serverKey is the server's *private* key

        super(inStr, outStr);

        // set the nonce counter
        nonce_l = Long.MIN_VALUE;

        // create a new KeyExchange object
        KeyExchange exch = new KeyExchange(rand, iAmServer);

        // each end of the secure channel prepares a message going out
        byte[] dh_out = exch.prepareOutMessage();
        super.sendMessage(dh_out);

        // each end also receives and processes a message from the other side
        // this creates the shared key from the D-H Key Exchange
        byte[] dh_in = super.receiveMessage();
        sharedKey = exch.processInMessage(dh_in);

        // the server then signs the shared key to be verified
        if (iAmServer) {
            super.sendMessage(serverKey.sign(sharedKey, rand));
        }
        // the client verifies the shared key, closes if verify fails
        else {
            if (!serverKey.verifySignature(sharedKey, super.receiveMessage())) {
                System.out.println("0");
                super.close();
            }
        }
    }

    public void sendMessage(byte[] message) throws IOException {
        // create the nonce
        byte[] nonce_a = ByteBuffer.allocate(Long.BYTES).putLong(nonce_l).array();

        // increment the nonce
        nonce_l++;

        // create a new AuthEncryptor for the message
        AuthEncryptor ae = new AuthEncryptor(sharedKey);
        byte[] encrypted = ae.encrypt(message, nonce_a, true);

        // send the message over the InsecureChannel
        super.sendMessage(encrypted);        
    }

    public byte[] receiveMessage() throws IOException {
        // receive the message from the InsecureChannel
        byte[] in = super.receiveMessage();  

        // extract the nonce from this input (last 8 bytes of input)
        byte[] nonce = new byte[8];
        nonce = Arrays.copyOfRange(in, in.length-8, in.length);

        // check the nonce to see if it is the correct value
        byte[] checkNonce = ByteBuffer.allocate(Long.BYTES).putLong(nonce_l).array();

        if (!Arrays.equals(nonce, checkNonce)) {
            return null;
        }

        // increment the nonce to check against
        nonce_l++;

        // create a new AuthEncryptor for the message
        AuthDecryptor ad = new AuthDecryptor(sharedKey);
        // in still contains the nonce appended, so will just pass that in
        byte[] decrypted = ad.decrypt(in);

        return decrypted;
    }
}
