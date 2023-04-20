package com.example.krypto;

import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.scene.paint.Color;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;


public class MainController{

    @FXML
    ProgressIndicator progressIndicator;

    @FXML
    TextArea encryptString;
    @FXML
    TextArea stringDecrypt;
    @FXML
    TextField txtPathDecrypt;
    @FXML
    TextField txtPathEncrypt;
    @FXML
    TextField encryptKeyInput;
    @FXML
    Label failedDe;
    @FXML
    Label failedEn;
    @FXML
    Button saveButton;

    @FXML
    Button encryptButton;
    @FXML
    Button decryptButton;
    @FXML
    Label infoLabel;

    @FXML
    AnchorPane mainBackground;

    @FXML
    RadioButton radioFile;
    @FXML
    RadioButton radioWindow;
    ToggleGroup toggleGroup = new ToggleGroup();




    File file;
    Stage stage = new Stage();

    String encryptKey;

    byte[] content;

    Scene scene;


    byte[] key;
    MainController controller;


    public void showStage() throws IOException {

        FXMLLoader fxmlLoader = new FXMLLoader(MainApplication.class.getResource("main-view.fxml"));
        Parent root = fxmlLoader.load();
        scene = new Scene(root, 750, 700);
        stage.setTitle("3DES encryption program");
        controller = fxmlLoader.getController();
       controller.defaultSettings();
        stage.setScene(scene);
        stage.show();

    }

    public void defaultSettings() {
        radioFile.setToggleGroup(toggleGroup);
        radioWindow.setToggleGroup(toggleGroup);
        progressIndicator.setVisible(false);
        saveButton.setVisible(false);
        mainBackground.setBackground(new Background(new BackgroundFill(Color.LIGHTBLUE,null,null)));
        encryptString.setBorder(new Border(new BorderStroke(Color.GREEN,BorderStrokeStyle.SOLID,new CornerRadii(3),new BorderWidths(2))));
        stringDecrypt.setBorder(new Border(new BorderStroke(Color.GREEN,BorderStrokeStyle.SOLID,new CornerRadii(3),new BorderWidths(2))));
        txtPathDecrypt.setBorder(new Border(new BorderStroke(Color.GREEN,BorderStrokeStyle.SOLID,new CornerRadii(3),new BorderWidths(2))));
        txtPathEncrypt.setBorder(new Border(new BorderStroke(Color.GREEN,BorderStrokeStyle.SOLID,new CornerRadii(3),new BorderWidths(2))));
        encryptKeyInput.setBorder(new Border(new BorderStroke(Color.GREEN,BorderStrokeStyle.SOLID,new CornerRadii(3),new BorderWidths(2))));
    }

    public void generateKey() {
        Random random = new Random();
        BigInteger bi = BigInteger.probablePrime(192,random);
        key = bi.toByteArray();
        StringBuilder sb = new StringBuilder();
        for (byte b : key) {
            sb.append(String.format("%02x", b));
        }
        sb.delete(0,2);


        String hex = sb.toString();
        key = HexFormat.of().parseHex(hex);
        encryptKeyInput.setText(HexFormat.of().formatHex(key));
    }

    public void decryptMessage() {

            TripleDES tdes = new TripleDES();
            content = tdes.decryptMessage(content, key);
            if(radioWindow.isSelected()) {
                encryptString.setText(new String(content, StandardCharsets.UTF_8));
            }
        saveButton.setVisible(true);
        saveButton.setText("Zapisz odszyfrowany");

    }

    public void encryptMessage() {

        TripleDES tdes = new TripleDES();
        content = tdes.encryptMessage(content,key);
        if(radioWindow.isSelected()) {
            stringDecrypt.setText(new String(Base64.getEncoder().encode(content)));
        }
        saveButton.setVisible(true);
        saveButton.setText("Zapisz zaszyfrowany");

    }



    public void setFileToEncrypt() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Proszę wybrać plik");
        file = fileChooser.showOpenDialog(stage);
        if(file!=null && file.getPath()!=null) {
            infoLabel.setText("Plik wybrany pomyślnie");
            txtPathEncrypt.setText(file.getPath());
            try {
                content = Files.readAllBytes(Paths.get(file.getPath()));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        txtPathDecrypt.setText("");

    }

    public void setWindow(){
        txtPathEncrypt.setText("");
        txtPathDecrypt.setText("");
        saveButton.setVisible(false);
    }
    public void setFile() {
        stringDecrypt.setText("");
        encryptString.setText("");
        saveButton.setVisible(false);
    }

    public void setFileToSaveEn() {

        FileChooser fileChooser = new FileChooser();
        FileChooser.ExtensionFilter pdfFilter = new FileChooser.ExtensionFilter("PDF files (*.pdf)", "*.pdf");
        fileChooser.getExtensionFilters().add(pdfFilter);
        FileChooser.ExtensionFilter extFilter = new FileChooser.ExtensionFilter("TXT files (*.txt)", "*.txt");
        fileChooser.getExtensionFilters().add(extFilter);
        FileChooser.ExtensionFilter binFilter = new FileChooser.ExtensionFilter("Binary Files (*.bin)", "*.bin");
        fileChooser.getExtensionFilters().add(binFilter);
        fileChooser.setTitle("Zapisz plik");
        file = fileChooser.showSaveDialog(stage);
        try(FileOutputStream stream = new FileOutputStream(file)) {
            stream.write(content);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
    public void setFileToDecrypt() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Proszę wybrać plik");
        file = fileChooser.showOpenDialog(stage);
        if(file!=null && file.getPath()!=null) {
            infoLabel.setText("Plik wybrany pomyślnie");
            txtPathDecrypt.setText(file.getPath());
            try {
                content = Files.readAllBytes(Paths.get(file.getPath()));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        txtPathEncrypt.setText("");

    }

    public void getEncryptInput() {
        progressIndicator.setVisible(true);
        if(radioWindow.isSelected() && encryptString.getText() == "") {
                infoLabel.setText("Proszę wprowadzić dane.");
                progressIndicator.setVisible(false);
                return;
        } else if(radioWindow.isSelected()) {
                content = encryptString.getText().getBytes();

        }
        if(encryptKeyInput.getText().length() == 48 && encryptKeyInput.getText().matches("[0-9A-Fa-f]{48}")) {
                encryptKey = encryptKeyInput.getText();
                key = HexFormat.of().parseHex(encryptKey);
                encryptMessage();
                encryptString.setText("");
        } else if(encryptKeyInput.getText().length() == 0) {
            generateKey();
            encryptMessage();
            encryptString.setText("");
        } else {
            infoLabel.setText("Wprowadzony klucz jest błędny! ");
        }
        progressIndicator.setVisible(false);

    }

    public void getDecryptInput() {
        progressIndicator.setVisible(true);
        if(radioWindow.isSelected()&&stringDecrypt.getText() == "") {
                progressIndicator.setVisible(false);
                infoLabel.setText("Proszę wprowadzić dane.");
                return;

        } else if(radioWindow.isSelected()) {
                content = Base64.getDecoder().decode(stringDecrypt.getText().getBytes());
        }
        if(encryptKeyInput.getText().length() == 48 && encryptKeyInput.getText().matches("[0-9A-Fa-f]{48}")) {
            encryptKey = encryptKeyInput.getText();
            key = HexFormat.of().parseHex(encryptKey);
            decryptMessage();
            stringDecrypt.setText("");

        } else {
            infoLabel.setText("Wprowadzony klucz jest błędny! ");
        }

        progressIndicator.setVisible(false);
    }
}