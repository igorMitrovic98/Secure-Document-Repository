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
import java.math.BigInteger;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.ResourceBundle;
import java.util.Scanner;

public class LoginController implements Initializable{

    X509Certificate userCertificate;
    X509Certificate CA;
    FileController fileController = new FileController();
    int attempts = 0;
    LoginController(X509Certificate certificate,X509Certificate CA){

        this.userCertificate = certificate;
        this.CA = CA;
    }

    CertificateController certificateController = new CertificateController();


    @FXML
    private Button btnLogin;

    @FXML
    private Label lblAttempt;

    @FXML
    private Label lblMsg;

    @FXML
    private PasswordField txtPass;

    @FXML
    private TextField txtUser;
    @FXML
    private Button btnClose;
    @FXML
    void BtnCloseClick(ActionEvent event) {
        ((Stage) btnClose.getScene().getWindow()).close();

    }



    @FXML
    void btnLoginClicked(ActionEvent event) throws Exception{


        File crlFile = new File(System.getProperty("user.dir")+File.separator+"root"+File.separator+"certs"+File.separator+"crl"+File.separator+"CRL1.crl");
        FileInputStream fileInputStream = new FileInputStream(crlFile);
        X509CRL CRL = CertUtil.loadCRL(fileInputStream);






        if(txtUser.getText().isEmpty() || txtPass.getText().isEmpty())
            return;

        List<String> list = Arrays.asList("SHA-1","MD2","MD5","SHA-224","SHA-256");
        int b=0,l=0;
        File database = new File("C:\\Users\\admin\\IdeaProjects\\CryptoFileSystem\\database\\baza.txt");
        String username = txtUser.getText();
        String password = txtPass.getText();
        String tmpPass = null;


            Scanner scanner = new Scanner(database);
            while (scanner.hasNextLine()) {
                if (scanner.nextLine().equals(username)) {
                    tmpPass = scanner.nextLine();
                    //System.out.println(tmpPass);
                    break;
                }
            }
            for (String element : list) {
                if (tmpPass.equals(encryptGivenPassword(password, element))) {
                    //extracting private key of user
                    extractPrivatekey(username, password);
                    b++;
                        if (CRL.getRevokedCertificate(userCertificate.getSerialNumber()) != null) {

                            certificateController.unrevokeCert(userCertificate);
                            l++;
                        }
                    //decrypting file with files
                    fileController.decryptFile();
                    //open User Interface form
                    UserInterfaceController userInterfaceController = new UserInterfaceController(username,password);
                    FXMLLoader fxmlLoader = new FXMLLoader(getClass().getResource("/UserInterface.fxml"));
                    fxmlLoader.setController(userInterfaceController);
                    Parent root = fxmlLoader.load();
                    Scene scene = new Scene(root);
                    Stage stage = new Stage();
                    stage.setTitle("UserInterface");
                    stage.setScene(scene);
                    stage.setResizable(false);
                    stage.initStyle(StageStyle.UNDECORATED);
                    stage.setOnCloseRequest((WindowEvent e) -> {
                        System.exit(0);
                    });
                    ((Stage) btnLogin.getScene().getWindow()).close();
                    stage.show();
                    break;
                }
                } if(b==0 && attempts < 2) {
                    attempts++;
                    lblMsg.setText("Incorrect credentials!");
                    lblAttempt.setText("You have " + (3 - attempts) + " more attempts before revoking your certificate!");
                    }
                else if (attempts == 2) {
                    lblMsg.setText("Incorrect credentials!");
                    lblAttempt.setText("Revoking your certificate. You have one more chance to enter correct credentials!");
                    File oldCRL =  new File("C:\\Users\\admin\\IdeaProjects\\CryptoFileSystem\\root\\certs\\crl\\CRL1.crl");
                    FileInputStream fi = new FileInputStream(oldCRL);
                    certificateController.revokeCert(userCertificate,fi);
                    fi.close();
                    attempts++;}
                else if (attempts == 3 && l==0 ){
                    final FXMLLoader fxmlLoader = new FXMLLoader(getClass().getResource("/Registration.fxml"));
                    RegistrationController registrationController = new RegistrationController();
                    fxmlLoader.setController(registrationController);
                    Parent root = fxmlLoader.load();
                    Stage stage = new Stage();
                    Scene scene = new Scene(root);
                    stage.setTitle("FileSystem");
                    stage.setScene(scene);
                    stage.setResizable(false);
                    stage.initStyle(StageStyle.UNDECORATED);
                    ((Stage) btnLogin.getScene().getWindow()).close();
                    stage.show();
        }
            }




    public String encryptGivenPassword(String password,String string) throws NoSuchAlgorithmException {

        MessageDigest md = MessageDigest.getInstance(string);
        byte[] messageDigest = md.digest(password.getBytes());
        BigInteger bigInteger = new BigInteger(1,messageDigest);
        return bigInteger.toString(16);

    }

    public void extractPrivatekey(String username,String password) throws Exception{
        Process p;
        String command = "openssl pkcs12 -in .\\root\\certs\\certs\\"+username+".pfx -nocerts -out .\\root\\certs\\"+username+"Key.key -passin pass:"+
                        password+" -passout pass:"+password;
        Runtime runtime = Runtime.getRuntime();
        p=runtime.exec(command);
    }



    @Override
    public void initialize(URL url, ResourceBundle rb){
        String commonName = (userCertificate.getSubjectDN().toString());
        String allias = commonName.substring(commonName.indexOf("=")+1);
        txtUser.setText(allias);
    btnLogin.setOnAction(event -> {
        try {
            btnLoginClicked(event);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    });
    btnClose.setOnAction(event -> BtnCloseClick(event));
    }


}
