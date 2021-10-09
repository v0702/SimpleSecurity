package security;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

public class Security {
    private static final SecureRandom secureRandomGenerator = new SecureRandom();
    private static final int BOCK_SIZE = 16;

    //----------------------------------------------------------------------------------------------------------------------------------------------
    //----------------------------------------------------------Encryption And Decryption-----------------------------------------------------------
    //--------------Aux--------------
    /**
     * Function to initialize an byte array to be used as iv for AES encryption
     * array size = 16Bytes
     * @return IvParameterSpec - returns the iv in the required state
     */
    private static IvParameterSpec generateIv() {
        byte[] iv = new byte[BOCK_SIZE];
        secureRandomGenerator.nextBytes(iv);
        return new IvParameterSpec(iv);
    }
    /**
     * Check if a byte array key is valid for use with AES-CBC (16/24/32 Bytes)
     * @param key byte[] - key to check size
     * @return true if key is okay to use else false
     */
    public static boolean checkKeyAES(byte[] key) {
        return key.length == 16 || key.length == 24 || key.length == 32;
    }
    /**
     * Function to encrypt a message.
     * Uses AES-CBC
     * iv is a 16 byte array that is appended at the start of the cipher
     * @param message byte[] - message desired to encrypt in byte array format
     * @param key byte[] - key to be used for encryption in byte array format
     * @return byte[] - encrypted message, return empty array if unable to cipher
     */
    //-------------------------------
    public static byte[] encryptSecurity(byte[] message,byte[] key) {
        //-------------------------Parameters Validation-------------------------
        if(message == null) {
            System.out.println("(ENCRYPTION) -> Message not valid, is null.");
            return new  byte[0];
        }
        else if(message.length==0){
            System.out.println("(ENCRYPTION) -> Message not valid, no size.");
            return new  byte[0];
        }
        else if(key == null) {
            System.out.println("(ENCRYPTION) -> Key not valid, is null.");
            return new  byte[0];
        }
        if(!checkKeyAES(key)){
            System.out.println("(ENCRYPTION) -> Key length not valid, needs to be 16,24 or 32 Bytes.\nKey length: "+ key.length);
            return new  byte[0];
        }
        //-----------------------------------------------------------------------
        //---------------------------Key and IV setup----------------------------
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivParameterSpec = generateIv();
        //-----------------------------------------------------------------------
        //------------------------------Encryption-------------------------------
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
            byte[] cipherBytes = cipher.doFinal(message);
            byte[] finalCipher = new byte[cipherBytes.length+ivParameterSpec.getIV().length];
            System.arraycopy(ivParameterSpec.getIV(),0,finalCipher,0,ivParameterSpec.getIV().length);
            System.arraycopy(cipherBytes,0,finalCipher,ivParameterSpec.getIV().length,cipherBytes.length);
            return finalCipher;
        } catch (Exception e) {
            System.out.println("Error encrypting message (AES): " + e.getMessage());
            return new byte[0];
        }
        //-----------------------------------------------------------------------
    }
    /**
     * Function to decipher a cipher.
     * Uses AES-CBC to decipher
     * iv is a 16 byte array that is kept at the start of the cipher
     * @param finalCipher byte[] - cipher in byte array format
     * @param key byte[] - byte array key
     * @return byte[] -  decrypted cipher, return empty array if unable to decipher
     */
    public static byte[] decipherSecurity(byte[] finalCipher,byte[] key) {
        //-------------------------Parameters Validation-------------------------
        if(!checkKeyAES(key)){
            System.out.println("(ENCRYPTION) -> Key length not valid, needs to be 16,24 or 32 Bytes.\nKey length: "+ key.length);
            return new  byte[0];
        }
        else if(finalCipher == null) {
            System.out.println("(ENCRYPTION) -> Cipher not valid");
            return new  byte[0];
        }
        else if(finalCipher.length==0){
            System.out.println("(DECRYPTION) -> Cipher not valid");
            return new  byte[0];
        }
        //-----------------------------------------------------------------------
        //---------------------------Key and IV setup----------------------------
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(finalCipher,0,BOCK_SIZE);
        //-----------------------------------------------------------------------
        //------------------------------Decryption-------------------------------
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
            return cipher.doFinal(finalCipher,BOCK_SIZE,finalCipher.length - BOCK_SIZE);
        } catch (Exception e) {
            System.out.println("Error decrypting cipher (AES): " + e.getMessage());
            return new byte[0];
        }
        //-----------------------------------------------------------------------
    }
    //----------------------------------------------------------------------------------------------------------------------------------------------
    //------------------------------------------------------------Formatting Variables--------------------------------------------------------------
    /**
     * @param byteArr byte array to be converted to a hex String
     * @return String representation of hex value.
     * <p>
     * source: https://howtodoinjava.com/java/java-security/how-to-generate-secure-password-hash-md5-sha-pbkdf2-bcrypt-examples/
     */
    public static String byteArrayToHex(byte[] byteArr) {
        if(byteArr == null)
            return "";

        BigInteger value = new BigInteger(1, byteArr);
        String hex = value.toString(16);

        int paddingLength = (byteArr.length * 2) - hex.length();
        if (paddingLength > 0) {
            return String.format("%0" + paddingLength + "d", 0) + hex;
        } else {
            return hex;
        }
    }
    /**
     * Convert an int number to its byte[] representation
     * @param number int - number to convert
     * @return byte[] - array byte representation of the int number
     */
    public static byte[] intToByte(int number) {
        return BigInteger.valueOf(number).toByteArray();
    }
    /**
     * Convert an byte[] number to its int representation
     * @param number byte[] - number to convert
     * @return int - int representation of the byte[] number
     */
    public static int byteToInt(byte[] number) {
        return new BigInteger(number).intValue();
    }
    /**
     * Transform a byte array to String -> UTF_8
     * @param byteArray byte [] - byte array to transform
     * @return String - return the byte array equivalent in string format UTF8
     */
    public static String byteArrayToString(byte[] byteArray) { return new String(byteArray, StandardCharsets.UTF_8); }

    public static String encodeBase64(String text) { return Base64.getEncoder().encodeToString(text.getBytes()); }
    public static String encodeBase64(byte[] textByte) { return Base64.getEncoder().encodeToString(textByte); }
    public static String decodeBase64(String textBase64) { return byteArrayToString(Base64.getDecoder().decode(textBase64)); }
    public static String decodeBase64(byte[] textByteBase64) { return byteArrayToString(Base64.getDecoder().decode(textByteBase64)); }
    public static byte[] decodeBase64Raw(String textBase64) { return Base64.getDecoder().decode(textBase64); }
    public static byte[] decodeBase64Raw(byte[] textByteBase64) { return Base64.getDecoder().decode(textByteBase64); }
    //----------------------------------------------------------------------------------------------------------------------------------------------
    //----------------------------------------------------------------------------------------------------------------------------------------------
    /**
     * Generate random bytes
     * @param byteSize - amount of bytes wanted
     * @return byte[] - byte array
     */
    public static byte[] generateRandomBytes(int byteSize) {
        byte[] bytesArray = new byte[byteSize];
        secureRandomGenerator.nextBytes(bytesArray);
        return bytesArray;
    }
}
