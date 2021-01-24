package src;

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

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

    public static String hash(String hasilHash){
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(hasilHash.getBytes());
            byte[] bytes = md.digest();

            StringBuilder sb = new StringBuilder();
            StringBuilder sb1 = new StringBuilder();
            for (byte aByte : bytes) {
                sb.append(Integer.toString((aByte & 0xff) + 0x100, 16).substring(1));
            }
            return sb.toString();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = null;
        keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048, new SecureRandom());
        KeyPair pair = keyGen.generateKeyPair();
        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();
        return new KeyPair(publicKey, privateKey);
    }

    public static String encrypt(String strToEncrypt, PublicKey publicKey){
        try {
            Cipher encryptCipher = Cipher.getInstance("RSA");
            encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] cipherText = encryptCipher.doFinal(strToEncrypt.getBytes(UTF_8));
            return Base64.getEncoder().encodeToString(cipherText);
        }
        catch (Exception e) {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }

    public static String decrypt(String strToDecrypt, PrivateKey privateKey){
        try {
            byte[] bytes = Base64.getDecoder().decode(strToDecrypt);
            Cipher decriptCipher = Cipher.getInstance("RSA");
            decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);
            return new String(decriptCipher.doFinal(bytes), UTF_8);
        }
        catch (Exception e) {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }

    public static PrivateKey getPrivateKey(String privKeyStr) throws InvalidKeySpecException, NoSuchAlgorithmException {
        PrivateKey privateKey = null;
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privKeyStr.getBytes()));
        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        try {
            privateKey = keyFactory.generatePrivate(keySpec);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return privateKey;

//        byte[] publicBytes = Base64.getDecoder().decode(privKeyStr);
//        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
//        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
////        PublicKey pubKey = keyFactory.generatePublic(keySpec);
//        return keyFactory.generatePrivate(keySpec);
    }
}
