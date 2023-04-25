package Controller;

import javafx.fxml.FXML;
import javafx.stage.FileChooser;
import javafx.stage.FileChooser.ExtensionFilter;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.MessageDigest;
import java.util.*;


public class FileController {


    @FXML
    String SingleFileChooser() throws NullPointerException{
        FileChooser fc =  new FileChooser();
        fc.getExtensionFilters().add(new ExtensionFilter("Certificate files","*.crt"));
        File file = fc.showOpenDialog(null);

        if(file != null)
            return file.getAbsolutePath();
        else return "File does not exist!";
    }
    String Path(String path) throws Exception{
    return "";
    }

    public void encryptFile() throws Exception {
        // Read the input file as bytes
        Path inputFile = Paths.get("C:\\Users\\admin\\IdeaProjects\\CryptoFileSystem\\root\\certs\\files.txt");
        byte[] inputBytes = Files.readAllBytes(inputFile);
        byte[] key = "C:\\Users\\admin\\IdeaProjects\\CryptoFileSystem\\root\\certs\\private\\caDER.key".getBytes();
        // Generate a secret key
        Key secretKey = new SecretKeySpec(keyTo32byte(key), "AES");

        // Create a cipher instance for encryption
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        // Encrypt the input bytes
        byte[] encryptedBytes = cipher.doFinal(inputBytes);

        // Write the encrypted bytes to an output file
        Path outputFile = Paths.get("C:\\Users\\admin\\IdeaProjects\\CryptoFileSystem\\root\\certs\\files.txt");
        Files.write(outputFile, encryptedBytes);

        System.out.println("File encrypted successfully.");
    }

    public void decryptFile() throws Exception {
        // Read the encrypted file as bytes
        Path inputFile = Paths.get("C:\\Users\\admin\\IdeaProjects\\CryptoFileSystem\\root\\certs\\files.txt");
        byte[] inputBytes = Files.readAllBytes(inputFile);
        byte[] key = "C:\\Users\\admin\\IdeaProjects\\CryptoFileSystem\\root\\certs\\private\\caDER.key".getBytes();
        // Generate a secret key
        Key secretKey = new SecretKeySpec(keyTo32byte(key), "AES");

        // Create a cipher instance for decryption
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        // Decrypt the input bytes
        byte[] decryptedBytes = cipher.doFinal(inputBytes);

        // Write the decrypted bytes to an output file
        Path outputFile = Paths.get("C:\\Users\\admin\\IdeaProjects\\CryptoFileSystem\\root\\certs\\files.txt");
        Files.write(outputFile, decryptedBytes);

        System.out.println("File decrypted successfully.");
    }
    public byte[] keyTo32byte(byte[] originalKey) throws Exception{
        return Arrays.copyOf(originalKey,32);
    }
    public void writeNewUserIntoFiles(String username) throws Exception{
        File file = new File("C:\\Users\\admin\\IdeaProjects\\CryptoFileSystem\\root\\certs\\files.txt");
        ArrayList<String> lista = new ArrayList<>();
        try{
            Scanner scanner = new Scanner(file);
            while(scanner.hasNextLine()){
                lista.add(scanner.nextLine());
            }
            scanner.close();

        } catch (FileNotFoundException e)
        {
            e.printStackTrace();
        }

        try {
            PrintStream p = new PrintStream(file);

            for(String string : lista) {
                p.println(string);
            }

            p.println(username);
            p.println("#");
            p.close();
             }catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }
    public void writeNewFileIntoFile(String fileName,String username,String digitalPrint)throws Exception{
        File file = new File("C:\\Users\\admin\\IdeaProjects\\CryptoFileSystem\\root\\certs\\files.txt");
        boolean condition = ifFileNameExists(file,fileName,username);
        ArrayList<String> lista = new ArrayList<>();
        ArrayList<String> lista2 = new ArrayList<>();
        try{
            Scanner scanner = new Scanner(file);
            while(scanner.hasNextLine()) {
                String tmp = scanner.nextLine();
                if (!tmp.equals(username)) {
                    lista.add(tmp);
                }
                else break;
            }
            //System.out.println(lista);
            scanner.close();

        } catch (FileNotFoundException e)
        {
            e.printStackTrace();
        }
        try{
            Scanner scanner = new Scanner(file);
            while(scanner.hasNextLine()) {
                if (scanner.nextLine().equals(username)) {
                    while (scanner.hasNextLine()) {
                        lista2.add(scanner.nextLine());
                    }
                }
            }
            //System.out.println(lista2);
            scanner.close();

        } catch (FileNotFoundException e)
        {
            e.printStackTrace();
        }
        try {
            PrintStream p = new PrintStream(file);

            for(String string : lista) {
                p.println(string);
            }
            //System.out.println(fileName);
            p.println(username);
            if (!condition) {
                p.println(fileName);
                p.println(digitalPrint);
            }
            for(String string : lista2) {
                p.println(string);
            }
            p.close();
        }catch (FileNotFoundException e) {
            e.printStackTrace();
        }


    }


    public void storeFileIntoSystem(File file) throws Exception{

    }

    private static Random random = new Random();
    public Integer randomInteger(){

        List<Integer> list = new ArrayList<>();
        list.add(4);
        list.add(5);
        list.add(6);
        list.add(7);
        list.add(8);
        int randomItem = random.nextInt(list.size());
        return list.get(randomItem);
    }
    public byte[] UserKeyTo32byte(byte[] originalKey,String fileName) throws Exception{
        byte [] name = fileName.getBytes();
        byte[] userKey= Arrays.copyOf(originalKey,(32 - name.length));
        byte[] combined = new byte[userKey.length + name.length];
        System.arraycopy(userKey, 0, combined, 0, userKey.length);
        System.arraycopy(name, 0, combined, userKey.length, name.length);
        return combined;
    }
    public void encryptUserFile(byte[] inputBytes,Integer n,Key secretKey,File file,String username) throws Exception {
        // Create a cipher instance for encryption
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        // Encrypt the input bytes
        byte[] encryptedBytes = cipher.doFinal(inputBytes);
        Integer tmp = n+1;
        // Write the encrypted bytes to an output file
        Path outputFile = Paths.get("C:\\Users\\admin\\IdeaProjects\\CryptoFileSystem\\root\\"+tmp+"\\"+FileNameHash(username+file.getName()+tmp));
        Files.write(outputFile, encryptedBytes);

        System.out.println("File encrypted successfully.");
    }

    public byte[] decryptUserFile(Key secretKey,byte[] inputBytes) throws Exception {
        try {

            // Create a cipher instance for encryption
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
//        byte[] iv = new byte[cipher.getBlockSize()];
//        SecureRandom random = new SecureRandom();
//        random.nextBytes(iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);

            // Decrypt the input bytes
            System.out.println("File decrypted successfully.");
            return cipher.doFinal(inputBytes);
        }catch (Exception e){
            System.out.println("Error during decryption: " + e.getMessage());
            return inputBytes;
        }

    }
    public static byte[] combineFiles(File[] files) throws IOException {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            for (File file : files) {
                try (FileInputStream fis = new FileInputStream(file)) {
                    byte[] buffer = new byte[1024];
                    int bytesRead;
                    while ((bytesRead = fis.read(buffer)) != -1) {
                        baos.write(buffer, 0, bytesRead);
                    }
                }
            }
            return baos.toByteArray();
        }
    }
    public boolean ifFileNameExists(File file,String fileName,String username) throws Exception {
        Scanner scanner = new Scanner(file);
        String line;
        boolean foundUsername = false;
        boolean foundFile = false;
        while (scanner.hasNextLine()) {
            line = scanner.nextLine().trim();
            if (line.equals(username)) {
                System.out.println("Found username: " + username);
                foundUsername = true;
                continue;
            }
            else
            if (foundUsername && line.equals("#")) {
                System.out.println("Found delimiter");
                break;
            }
            else
            if (foundUsername && line.equals(fileName)) {
                System.out.println("Found file: " + fileName);
                foundFile = true;
                break;
            }
        }
        scanner.close();
        return foundFile;
    }
    public String calculateFileHash(File file,String username)throws Exception{

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        FileInputStream fis = new FileInputStream(file);
        byte[] dataBytes = new byte[1024];
        int bytesRead;
        while ((bytesRead = fis.read(dataBytes)) != -1) {
            md.update(dataBytes, 0, bytesRead);
        }
        byte[] mdBytes = md.digest();
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < mdBytes.length; i++) {
            sb.append(Integer.toString((mdBytes[i] & 0xff) + 0x100, 16).substring(1));
        }
        return sb.toString();
    }
    public String findFileHash(String fileName,String username){
        File file = new File("C:\\Users\\admin\\IdeaProjects\\CryptoFileSystem\\root\\certs\\files.txt");
        Scanner scanner = null;
        try {
            scanner = new Scanner(file);
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }
        String line;
        boolean foundUsername = false;
        while (scanner.hasNextLine()) {
            line = scanner.nextLine().trim();
            if (line.equals(username)) {
                System.out.println("Found username: " + username);
                foundUsername = true;
                continue;
            }
            if (foundUsername && line.equals("#")) {
                System.out.println("Found delimiter");
                break;
            }
            if (foundUsername && line.equals(fileName)) {
                System.out.println("Found file: " + fileName);
                String print = scanner.nextLine();
                System.out.println(print);
               return print;
            }
        }
        scanner.close();
        return "";
    }
    public String FileNameHash(String filename){
        int hash = Objects.hash(filename);
        return Integer.toHexString(hash);
    }

    public void privateKeyRSA(String username,String password)throws Exception{
        Process p;
        String command = "openssl rsa -in .\\root\\certs\\"+username+"Key.key -inform PEM -outform DER -out .\\root\\certs\\"+username+"Key1.key -passin pass:"+
                password;
        Runtime runtime = Runtime.getRuntime();
        p=runtime.exec(command);
    }
}
