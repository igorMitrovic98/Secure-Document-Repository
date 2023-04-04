package Controller;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.ListView;
import javafx.scene.control.SelectionMode;
import javafx.stage.FileChooser;

import java.io.File;
import java.io.FileNotFoundException;
import java.net.URL;
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
    void btnUploadClicked() {
        File file = new File(SingleFileChooser());
        btnUpload.setDisable(true);
        lblFileName.setText(file.getName());
        lblTmp.setText(file.getAbsolutePath());
        lblTmp.setVisible(false);
        btnConfirm.setDisable(false);
    }

    @FXML
    void btnConfirmClicked() {
        fileController.writeNewFileIntoFile(lblFileName.getText(), username);
    }

    @Override
    public void initialize(URL url, ResourceBundle rb)  {
        btnConfirm.setDisable(true);
        btnRetrieve.setDisable(true);
        btnConfirm.setOnAction(event -> btnConfirmClicked());
        btnUpload.setOnAction(event -> btnUploadClicked());
        initializeListView(username);
        lwFiles.setOnMouseClicked(event -> ListViewClicked());




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

    public void initializeListView(String username){
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
            String line = scanner.nextLine();
            if (line.contains(username)) {
                process = true;
            }
            if (process) {
                list.add(line);
            }
            if (line.contains("#")) {
                process = false;
            }
        }
            scanner.close();
        list.remove(0);
        list.remove(list.size() - 1);
        ObservableList<String> items = FXCollections.observableArrayList(list);
        //System.out.println(list);
        //System.out.println(items);
        lwFiles.setItems(FXCollections.observableList(items));
        lwFiles.getSelectionModel().setSelectionMode(SelectionMode.SINGLE);
    }
    public void ListViewClicked(){
        btnRetrieve.setDisable(false);
    }
}