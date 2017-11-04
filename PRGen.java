/**********************************************************************************/
/* PRGen.java                                                                     */
/* ------------------------------------------------------------------------------ */
/* DESCRIPTION: This class implements a backtracking-resistant pseudo-random      */
/*              generator.  It should produce a sequence of pseudo-random bits    */
/*              specified by a key of length <KEY_SIZE_BYTES>.                    */
/* ------------------------------------------------------------------------------ */
/* YOUR TASK: You must write a generator with the following properties:           */
/*            (1) It must be pseudo-random, meaning that there is no way to       */
/*                distinguish its output from that of a truly random generator    */
/*                unless you know the key.                                        */
/*            (2) It must be deterministic, meaning that, if two programs create  */
/*                generators with the same seed and make the same sequence of     */
/*                calls, they should receive the same sequence of bytes.          */
/*            (3) It must be backtracking-resistant, meaning that, even if an     */
/*                adversary observes the full state of the generator at time t,   */
/*                the adversary will not be able to determine the output of the   */
/*                generator at any time prior to t.                               */
/* ------------------------------------------------------------------------------ */
/* NOTE: This class extends java.util.Random, which means that, once implemented, */
/*       you have access to a number of useful utility methods for free.  We      */
/*       highly recommend that you look up the java.util.Random documentation to  */
/*       understand the full API of this class.  For example, you can write       */
/*           prg.nextBytes(outArray);                                             */
/*       instead of                                                               */
/*           for (int i = 0; i < outArray.length; i++) outArray[i] = prg.next();  */
/* ------------------------------------------------------------------------------ */
/* USAGE: Create a generator with a key k by calling the constructor:             */
/*            PRGen prg = new PRGen(k);                                           */
/*                                                                                */
/*        Retrieve pseudo-random bits from the sequence corresponding to key k by */
/*        calling next() (or any related method in the java.util.Random API):     */
/*            int r1 = prg.next(8);  // 8  pseudo-random bits                     */
/*            int r2 = prg.next(32); // 32 pseudo-random bits                     */
/*                                                                                */
/**********************************************************************************/

public class PRGen extends java.util.Random {
    // Class constants.
    public static final int KEY_SIZE_BYTES = PRF.KEY_SIZE_BYTES;

    // Instance variables.
    private PRF prf;

    public PRGen(byte[] key) {
        super(); // Calls the parent class's constructor.  Leave this here.
        assert key.length == KEY_SIZE_BYTES;

        // initializes a new PRF based on the secret key
        prf = new PRF(key);  
    }

    // Returns an integer whose low-order <bits> bits are set pseudo-randomly. The
    // higher-order bits should be set to 0.
    protected int next(int bits) {
        assert 0 < bits && bits <= 32;

        int result = 0;
        // will be used later to bitwise OR
        byte[] zero = new byte[] {0};
        byte[] one = new byte[] {1};

        // get a new output from the PRF
        byte[] rand = prf.eval(one);

        for (int i = 0; i < bits; i++) {

            // left shift the result array
            result = result << 1;

            // bitwise or the array with 1 if bit is 1, otherwise, bitwise or with 0
            if (rand[i] > 0) result |= 1;
            else result |= 0;
        }
        // advance the PRF
        prf = new PRF(prf.eval(zero));
        return result;
    }

    public static void main(String[] args){
        byte[] key = new byte[32];

        PRGen prg = new PRGen(key);

        System.out.println("8-bit int: " + prg.next(8));
        System.out.println("16-bit int: " + prg.next(16));
        System.out.println("32-bit int: " + prg.next(32));
    }
}