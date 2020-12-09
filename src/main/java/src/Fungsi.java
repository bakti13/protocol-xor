package src;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Fungsi {

    public static final String ERROR = "ERROR!";
    public static final String VALID = "VALID";

    public static String encryptThisString(String input) {
        try {
            // getInstance() method is called with algorithm SHA-1
            MessageDigest md = MessageDigest.getInstance("SHA-1");

            // digest() method is called
            // to calculate message digest of the input string
            // returned as array of byte
            byte[] messageDigest = md.digest(input.getBytes());

            // Convert byte array into signum representation
            BigInteger no = new BigInteger(1, messageDigest);

            // Convert message digest into hex value

            // Add preceding 0s to make it 32 bit
//            while (hashtext.length() < 32) {
//                hashtext = "0" + hashtext;
//            }

            // return the HashText
            return no.toString(16);
        }

        // For specifying wrong message digest algorithms
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static void delay(int milisecond) {
        try {
            Thread.sleep(milisecond);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        }
    }

    public static String xor(String str1, String str2) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < str1.length(); i++) {
            result.append(str1.charAt(i) ^ str2.charAt(i));
        }
        return result.toString();
    }


}
