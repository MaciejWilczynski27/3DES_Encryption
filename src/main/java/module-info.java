module com.example.krypto {
    requires javafx.controls;
    requires javafx.fxml;


    opens com.example.krypto to javafx.fxml;
    exports com.example.krypto;
}