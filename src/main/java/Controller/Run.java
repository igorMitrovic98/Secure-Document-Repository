package Controller;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.stage.Stage;
import javafx.scene.Parent;
import java.net.URL;

import javafx.stage.WindowEvent;
import Controller.RegistrationController;

import java.io.IOException;

public class Run extends Application {

    @Override
    public void start(Stage stage) throws Exception {


            final FXMLLoader fxmlLoader = new FXMLLoader(getClass().getResource("/Registration.fxml"));
            RegistrationController registrationController = new RegistrationController();
            fxmlLoader.setController(registrationController);
            Parent root = fxmlLoader.load();
            Scene scene = new Scene(root);
            stage.setTitle("FileSystem");
            stage.setScene(scene);
            stage.setResizable(false);
            stage.show();


    }

    public static void main(String[] args) {
        launch(args);
    }
}