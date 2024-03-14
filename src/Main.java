import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Iveskite E encryption, jei norite desifruoti spauskite D ");
        String choice = scanner.nextLine();

        if (choice.equals("e")) {
            System.out.println("Iveskite teksta: ");
            String plaintext = scanner.nextLine();
            System.out.println("Iveskite 16 simboliu RAKTA: ");
            String key = scanner.nextLine();

            String encryptedText = encrypt(plaintext, key);
            System.out.println("Uzsifruotas tekstas: " + encryptedText);

            saveToFile("encrypted_text.txt", encryptedText);
        } else if (choice.equals("d")) {
            String encryptedText = readFromFile("encrypted_text.txt");
            System.out.println("Iveskite 16 simboliu RAKTA: ");
            String key = scanner.nextLine();

            String decryptedText = decrypt(encryptedText, key);
            System.out.println("Desifruotas tekstas: " + decryptedText);
        } else {
            System.out.println("Iveskite E arba D");
        }
    }

    public static String encrypt(String plaintext, String key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] ivBytes = cipher.getIV();
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());
        byte[] combinedBytes = new byte[ivBytes.length + encryptedBytes.length];
        System.arraycopy(ivBytes, 0, combinedBytes, 0, ivBytes.length);
        System.arraycopy(encryptedBytes, 0, combinedBytes, ivBytes.length, encryptedBytes.length);
        return Base64.getEncoder().encodeToString(combinedBytes);
    }

    public static String decrypt(String encryptedText, String key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
        byte[] encryptedBytesWithIV = Base64.getDecoder().decode(encryptedText);
        byte[] ivBytes = new byte[16];
        System.arraycopy(encryptedBytesWithIV, 0, ivBytes, 0, ivBytes.length);
        byte[] encryptedBytes = new byte[encryptedBytesWithIV.length - ivBytes.length];
        System.arraycopy(encryptedBytesWithIV, ivBytes.length, encryptedBytes, 0, encryptedBytes.length);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(ivBytes));
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes);
    }

    public static void saveToFile(String filename, String content) throws IOException {
        Files.write(Paths.get(filename), content.getBytes());
    }

    public static String readFromFile(String filename) throws IOException {
        return new String(Files.readAllBytes(Paths.get(filename)));
    }
}
