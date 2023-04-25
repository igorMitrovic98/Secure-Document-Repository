package Controller;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.*;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.util.ArrayList;
import java.util.ResourceBundle;
import java.util.Scanner;

public class UserInterfaceController implements Initializable {

    String username;
    String password;

    UserInterfaceController(String username, String password) {
        this.username = username;
        this.password = password;
    }

    FileController fileController = new FileController();

    @FXML
    public Button btnRetrieve;
    @FXML
    public Button btnUpload;
    @FXML
    public ListView<String> lwFiles = new ListView<>();
    @FXML
    public Label lblFileName;
    @FXML
    public Label lblTmp;
    @FXML
    public Button btnConfirm;
    @FXML
    public Button btnClose;
    @FXML
    public Label lblMsg;

    @FXML
    void BtnCloseClick(ActionEvent event)throws Exception {
        File file = new File("C:\\Users\\admin\\IdeaProjects\\CryptoFileSystem\\root\\certs\\"+username+"Key.key");
        file.delete();
        fileController.encryptFile();
        ((Stage) btnClose.getScene().getWindow()).close();

    }

    @FXML
    void btnUploadClicked() throws Exception {
        File file = new File(SingleFileChooser());
        btnUpload.setDisable(true);
        lblFileName.setText(file.getName());
        lblTmp.setText(file.getAbsolutePath());
        lblTmp.setVisible(false);
        btnConfirm.setDisable(false);
        lblMsg.setText("");

        }

    @FXML
    void btnConfirmClicked() throws  Exception {
        File files = new File("C:\\Users\\admin\\IdeaProjects\\CryptoFileSystem\\root\\certs\\files.txt");
        File inputFile = new File(lblTmp.getText());
        if(!fileController.ifFileNameExists(files,lblFileName.getText(),username)) {
            fileController.writeNewFileIntoFile(lblFileName.getText(), username, fileController.calculateFileHash(inputFile,username));
            byte[] key = ("C:\\Users\\admin\\IdeaProjects\\CryptoFileSystem\\root\\certs\\" + username + "Key.key").getBytes();
            Path filePath = Paths.get(lblTmp.getText().replace("\\", "\\\\"));
            File file = new File(lblTmp.getText().replace("\\", "\\\\"));
            Key secretKey = new SecretKeySpec(fileController.UserKeyTo32byte(key, file.getName()), "AES");
            Integer n = fileController.randomInteger();
            byte[] fileBytes = Files.readAllBytes(filePath);
            int chunkSize = fileBytes.length / n;
            int remainingBytes = fileBytes.length % n;

            for (int i = 0; i < n; i++) {
                int startId = i * chunkSize;
                int endId = (i + 1) * chunkSize;
                if (i == n - 1) {
                    endId += remainingBytes;
                }
                byte[] chunkBytes = new byte[endId - startId];
                System.arraycopy(fileBytes, startId, chunkBytes, 0, chunkBytes.length);
                fileController.encryptUserFile(chunkBytes, i, secretKey, file,username);

            }
            initializeListView(username);
            lwFiles.refresh();
            btnUpload.setDisable(false);
            btnConfirm.setDisable(true);
            lblTmp.setText("");
            lblFileName.setText("");
        }
        else {
            lblMsg.setText("Please change the name of your input file. File with that name already exists!");
            btnUpload.setDisable(false);
            btnConfirm.setDisable(true);
            lblTmp.setText("");
            lblFileName.setText("");
        }
    }

    @FXML
    void btnRetrieveClicked() throws Exception{
        String fileName = lwFiles.getSelectionModel().getSelectedItem();
        File outputFile = new File("C:\\Users\\admin\\Desktop\\KriptoFiles\\"+fileName);
        byte[] key = ("C:\\Users\\admin\\IdeaProjects\\CryptoFileSystem\\root\\certs\\" + username + "Key.key").getBytes();
        Key secretKey = new SecretKeySpec(fileController.UserKeyTo32byte(key, fileName), "AES");
        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        for(int i = 0; i < 8; i++){
            Integer tmp = i+1;
            try{
            Path filePath = Paths.get("C:\\Users\\admin\\IdeaProjects\\CryptoFileSystem\\root\\"+tmp+"\\"+fileController.FileNameHash(username+fileName+tmp));
            byte[] inputBytes = Files.readAllBytes(filePath);
            byte[] decryptedBytes = fileController.decryptUserFile(secretKey,inputBytes);

            bos.write(decryptedBytes);
            }catch (NoSuchFileException exception){

            }

        }
        FileOutputStream fileOutputStream = new FileOutputStream(outputFile);
        fileOutputStream.write(bos.toByteArray());
        fileOutputStream.flush();
        String outputDigitalPrint = fileController.calculateFileHash(outputFile,username);
        String originalDigitalPrint = fileController.findFileHash(fileName,username);
        if(!outputDigitalPrint.equals(originalDigitalPrint)){
            Alert alert = new Alert(Alert.AlertType.WARNING);
            alert.setTitle("WARNING!");
            alert.setHeaderText(null);
            alert.setContentText("Data has been compromised!");

            alert.showAndWait();
        }
        btnRetrieve.setDisable(true);

    }

    @Override
    public void initialize(URL url, ResourceBundle rb)  {
        btnConfirm.setDisable(true);
        btnRetrieve.setDisable(true);
        try {
            initializeListView(username);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        btnConfirm.setOnAction(event -> {
            try {
                btnConfirmClicked();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        btnUpload.setOnAction(event -> {
            try {
                btnUploadClicked();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        lwFiles.setOnMouseClicked(event -> ListViewClicked());
        btnClose.setOnAction(event -> {
            try {
                BtnCloseClick(event);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        btnRetrieve.setOnAction(event -> {
            try {
                btnRetrieveClicked();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });


    }

    @FXML
    String SingleFileChooser() throws NullPointerException {
        FileChooser fc = new FileChooser();
        fc.getExtensionFilters().add(new FileChooser.ExtensionFilter("All files", "*"));
        File file = fc.showOpenDialog(null);

        if (file != null)
            return file.getAbsolutePath();
        else return "File does not exist!";
    }

    String Path(String path) throws Exception {
        return "";
    }

    public void initializeListView(String username)throws Exception{
        File file = new File("C:\\Users\\admin\\IdeaProjects\\CryptoFileSystem\\root\\certs\\files.txt");
        ArrayList<String> list = new ArrayList<>();
        Scanner scanner = null;
        boolean process = false;
        try {
            scanner = new Scanner(file);
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }
        while (scanner.hasNextLine()) {
            String line = scanner.nextLine().trim();
            System.out.println(line);
            if (line.equals(username)) {
                process = true;
                System.out.println("Username Found!");
            }else
            if (process && line.contains(".")) {
                list.add(line);
                System.out.println("Item Added!");
            }else
            if (line.contains("#") && process == true) {
                process = false;
                break;
            }
        }
            scanner.close();
        System.out.println(list);
        ObservableList<String> items = FXCollections.observableArrayList(list);
        lwFiles.setItems(FXCollections.observableList(items));
        lwFiles.getSelectionModel().setSelectionMode(SelectionMode.SINGLE);
        System.out.println(lwFiles.getItems());
    }
    public void ListViewClicked(){
        btnRetrieve.setDisable(false);
    }
}