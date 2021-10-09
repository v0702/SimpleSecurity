package security;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class PBKDF2 {

    /**
     * @param password   String password from which a derived key is generated
     * @param iterations int number of iterations (recommended values: 4096, 2000, 10000, 5000 100000)
     * @param keyLength  int length of the generated key in bits (recommended: 512)
     * @return String representation of derived key generated
     * <p>
     * Examples of pseudorandom function for PBKDF2 include
     * HMAC with SHA-1, SHA-224, SHA-256, SHA-384, SHA-512
     */
    private static Key hashPassword(String algorithm, String password, int iterations, int keyLength, int saltSize) {

        char[] passwordChars = password.toCharArray();
        byte[] saltBytes = Security.decodeBase64Raw("CoqmEd2A9VnWiGbn/2lRiGmJBpR7BtBnbt10wK7OjaCmthcc4hR1IL1EPXRLPFRZFrep141RckTGi/acDCbpU3B9SylZGdMyhuRQVFO/tSFWdn6LrKmLqMBI3mwnx59o2M+pPtdmv1nIUkC5jFfTIO5z5IJ/jPxRnIkGCHtYm70=");
        //byte[] saltBytes = Security.generateRandomBytes(saltSize);// cryptographic salt (recommended: at least 64 bits or better 128)

        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHMAC" + algorithm);
            PBEKeySpec spec = new PBEKeySpec(passwordChars, saltBytes, iterations, keyLength);
            SecretKey key = skf.generateSecret(spec);
            byte[] byteKey = key.getEncoded();

            return new Key(byteKey,saltBytes);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            System.out.println("The provided algorithm is not valid, check -help to more details");
            return new Key(new byte[0],new byte[0]);
        }
    }

    public static Key generateKey(String pass, String algo, int iter, int keyLength, int saltSize) {

        if (pass == null || pass.equals("")) {
            System.out.println("no password");//TODO
            return new Key(new byte[0],new byte[0]);
        }
        if (algo == null || algo.equals("")) {
            algo = "sha512";
        }
        if (iter <= 0) {
            iter = 1000;
        }
        if (keyLength <= 0) {
            keyLength = 512;
        }
        if (saltSize <= 0) {
            saltSize = 64;
        }

        return hashPassword(algo, pass, iter, keyLength, saltSize);
    }

    /*public static Key handlePBKDFParams(String[] args) {
        String algo = "sha512";
        String pass = "";
        int iter = 1000;
        int keyLength = 512;
        int saltSize = 64;

        *//*int helpIndex = lookOptions(args, new String[]{"-help", "-h", "--help"});
        if (helpIndex != -1) {
            System.out.println("""
                    PBKDF2 (Password-Based Key Derivation Function 2) is a key derivation function,
                    used to reduce vulnerabilities of brute-force attacks.

                    PBKDF2 Commands =====================================================================================================
                    -h -help --help, displays the help menu.
                    -p -password --password, password from which a derived key is generated. (mandatory)
                    -a -algo --algo, algorithm used to generate the derived key. {SHA1, SHA224, SHA256, SHA384, SHA512} (Default: SHA512)
                    -i -iter --iter, number of iterations desired. (Default: 1000)
                    -l -length --length, bit-length of the derived key. (Default: 512 bits)
                    =====================================================================================================================
                    """);
            return;
        }*//*

        int algoIndex = lookOptions(args, new String[]{"-a", "-algo", "--algo"});
        if (algoIndex != -1 && (algoIndex + 1) <= args.length - 1){
            algo = args[algoIndex + 1];
        }

        int passwordIndex = lookOptions(args, new String[]{"-p", "-password", "--password"});
        if (passwordIndex != -1 && (passwordIndex + 1) <= (args.length - 1)) {
            pass = args[passwordIndex + 1];
        } else {
            System.out.println("Must provide a password, check -help for more details");
            return new Key(new byte[0], new byte[0]);
        }

        int iterIndex = lookOptions(args, new String[]{"-i", "-iter", "--iter"});
        if (iterIndex != -1 && (iterIndex + 1) <= args.length - 1) {
            try {
                iter = Integer.parseInt(args[iterIndex + 1]);
            } catch (Exception e) {
                System.out.println("Iteration must be a number, using default value (1000)");
            }
        }

        int lengthIndex = lookOptions(args, new String[]{"-l", "-length", "--length"});
        if (lengthIndex != -1 && (lengthIndex + 1) <= args.length - 1) {
            try {
                keyLength = Integer.parseInt(args[lengthIndex + 1]);
            } catch (Exception e) {
                System.out.println("Length must be a number, using default value (512 bits)");
            }
        }
        return hashPassword(algo, pass, iter, keyLength, saltSize);
    }*/

    /**
     * This function returns the index (position) on the String array where any word from the words array was found
     * @param options String[] - array where to look for words
     * @param words String[] - array of the words to look for
     * @return int - index of the position where the word was found, returns -1 if no word was found
     */
    private static int lookOptions(String[] options,String[] words) {
        for(int i=0;i<options.length;i++) {
            for(String word : words) {
                if(options[i].equals(word))
                    return i;
            }
        }
        return -1;
    }
}