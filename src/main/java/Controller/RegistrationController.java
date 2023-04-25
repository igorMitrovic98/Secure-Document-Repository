package Controller;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.fxml.Initializable;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import javafx.stage.Stage;
import javafx.stage.StageStyle;
import javafx.stage.WindowEvent;
import net.i2p.crypto.CertUtil;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.PrintStream;
import java.math.BigInteger;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.*;


public class RegistrationController implements Initializable {

    FileController fileController = new FileController();
    CertificateController certificateController = new CertificateController();

    @FXML
    private Button btnClose;

    @FXML
    private Button btnContinue;

    @FXML
    private Button btnInsert;

    @FXML
    private Button btnSIgnUp;

    @FXML
    public Label lblCert;

    @FXML
    private PasswordField txtPassword;

    @FXML
    private TextField txtUsername;

    @FXML
    private PasswordField txtRepeat;

    @FXML
    private Label lblCorrect;

    @FXML
    private Label lblExist;

    @FXML
    private Label lblTmp;

    @FXML
    private Label lblVerify;

    @FXML
    void BtnCloseClick(ActionEvent event)throws Exception {
        fileController.encryptFile();
        ((Stage) btnClose.getScene().getWindow()).close();

    }

    @FXML
    void btnInsertClick(ActionEvent event) throws Exception {
        File file = new File(fileController.SingleFileChooser());
        lblCert.setText("Selected Certificate:: "+file.getName());
        btnInsert.setDisable(true);
        lblTmp.setText(file.getAbsolutePath());
        lblTmp.setVisible(false);
        btnContinue.setDisable(false);

    }

    @FXML
    void btnContinueClicked(ActionEvent event) throws Exception{

        //certificateController.createCRL();
        //finding ca cert
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        File CAcertificate = new File("C:\\Users\\admin\\IdeaProjects\\CryptoFileSystem\\root\\certs\\ca.crt");
        FileInputStream input = new FileInputStream(CAcertificate);
        X509Certificate Cacert = (X509Certificate) factory.generateCertificate(input);


        //finding user certificate
        CertificateFactory factory1 = CertificateFactory.getInstance("X.509");
        String filePath = lblTmp.getText();
        //String decodedPath = filePath.replace("\\","\\\\");
        FileInputStream input1 = new FileInputStream(filePath.replace("\\","\\\\"));
        X509Certificate cert = (X509Certificate)factory1.generateCertificate(input1);
        //check if certificate is revoked
        File crlFile = new File("C:\\Users\\admin\\IdeaProjects\\CryptoFileSystem\\root\\certs\\crl\\CRL1.crl");
        FileInputStream fileInputStream = new FileInputStream(crlFile);
        X509CRL CRL = CertUtil.loadCRL(fileInputStream);
        if(CRL.getRevokedCertificate(cert.getSerialNumber()) != null){
            lblVerify.setText("Certificate is revoked!");
            lblTmp.setText("");
            lblCert.setText("");
            btnInsert.setDisable(false);
        }
        else {
        try {
            //check if date and issuer are valid
            cert.checkValidity();
            cert.verify(Cacert.getPublicKey());
            if(cert.equals(Cacert)){
                Exception exception = new Exception();
                throw exception;
            }
            System.out.println("Verified OK");
            //open login form
            LoginController loginController = new LoginController(cert,Cacert);
            FXMLLoader fxmlLoader = new FXMLLoader(getClass().getResource("/Login.fxml"));
            fxmlLoader.setController(loginController);
            Parent root = fxmlLoader.load();
            Scene scene = new Scene(root);
            Stage stage = new Stage();
            stage.setTitle("LoginForm");
            stage.setScene(scene);
            stage.setResizable(false);
            stage.initStyle(StageStyle.UNDECORATED);
            stage.setOnCloseRequest((WindowEvent e) -> { System.exit(0);});
            ((Stage) btnContinue.getScene().getWindow()).close();
            stage.show();


        }catch (Exception e) {
            System.out.println("Not Verified");
            lblVerify.setText("Not Verified!");
            lblTmp.setText("");
            lblCert.setText("");
            btnInsert.setDisable(false);
            btnContinue.setDisable(true);

        }
    }}

    @FXML
    void btnSIgnUpClicked(ActionEvent event) throws Exception {

        if(txtUsername.getText().isEmpty() || txtPassword.getText().isEmpty() || txtRepeat.getText().isEmpty())
            return;

        File file = new File("C:\\Users\\admin\\IdeaProjects\\CryptoFileSystem\\database\\baza.txt");
        String username = txtUsername.getText();
        String password = txtPassword.getText();
        ArrayList<String> lista = new ArrayList<>();
        CertificateController userCert = new CertificateController();
        if(!password.equals(txtRepeat.getText())){
            lblCorrect.setText("Passwords are not equal!");
            return;}
            lblCorrect.setText("");

        Scanner s = null;
        try {
            s = new Scanner(file);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        while(s.hasNextLine()){
         String tmp = s.nextLine();
         if(tmp.equals(username)){
             lblExist.setText("Username taken!");
             return;}
         else
             lblExist.setText("");
        }
        s.close();

        try{
          Scanner  scanner = new Scanner(file);
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
            p.println(encryptPassword(password));
            p.close();
            userCert.createUserCertificate(username,password);
            userCert.giveUserCert(username,password);
            lblExist.setText("You got your user Certificate!");
            fileController.writeNewUserIntoFiles(username);


        } catch (FileNotFoundException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

       btnSIgnUp.setDisable(true);

    }


    @Override
    public void initialize (URL url, ResourceBundle rb) {

    btnClose.setOnAction(event1 -> {
        try {
            BtnCloseClick(event1);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    });
    btnSIgnUp.setOnAction(event -> {
        try {
            btnSIgnUpClicked(event);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    });
    btnInsert.setOnAction(event -> {
        try {
            btnInsertClick(event);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    });
    btnContinue.setOnAction(event -> {
        try {
            btnContinueClicked(event);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    });

    }

     private static Random random = new Random();
    public String randomString(){

        List<String> list = new ArrayList<>();
        list.add("SHA-1");
        list.add("MD2");
        list.add("MD5");
        list.add("SHA-224");
        list.add("SHA-256");
        int randomItem = random.nextInt(list.size());
        return list.get(randomItem);
    }


    public String encryptPassword(String password) throws NoSuchAlgorithmException{

        MessageDigest md = MessageDigest.getInstance(randomString());
        byte[] messageDigest = md.digest(password.getBytes());
        BigInteger bigInteger = new BigInteger(1,messageDigest);
        return bigInteger.toString(16);

    }


}
