package com.example.krypto;

import javafx.application.Application;
import javafx.stage.Stage;
import java.io.IOException;

public class MainApplication extends Application {
    @Override
    public void start(Stage stage) throws IOException {
        MainController mc = new MainController();
        mc.showStage();

    }

    public static void main(String[] args) {

        launch();
    }
}