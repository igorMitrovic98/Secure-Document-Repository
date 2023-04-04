package Controller;

import javafx.fxml.FXML;
import javafx.stage.FileChooser;
import javafx.stage.FileChooser.ExtensionFilter;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Scanner;


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
    public void writeNewFileIntoFile(String fileName,String username){
        File file = new File("C:\\Users\\admin\\IdeaProjects\\CryptoFileSystem\\root\\certs\\files.txt");
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
            System.out.println(lista);
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
            System.out.println(lista2);
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
            p.println(fileName);
            for(String string : lista2) {
                p.println(string);
            }
            p.close();
        }catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }
    }

