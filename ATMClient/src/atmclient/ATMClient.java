/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package atmclient;

/**
 *
 * @author Avneet
 */
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;

public class ATMClient {

    private static final String SERVER_ADDRESS = "localhost";
    private static final int SERVER_PORT = 15008;
    private static final String ALGORITHM = "AES/ECB/PKCS5Padding";
    private static final String MAC_ALGORITHM = "HmacSHA256";
    private static final String keyString = "mySimpleSharedKey";
    private static final byte[] keyBytes = keyString.getBytes(StandardCharsets.UTF_8);
    private static final SecretKey sharedKey = new SecretKeySpec(Arrays.copyOf(keyBytes, 16), "AES");
    private static final SecretKey macKey = new SecretKeySpec(Arrays.copyOf(keyBytes, 16), MAC_ALGORITHM);
    private static final atmgui loginframe = new atmgui();
    private static final options optionsframe = new options();
    private static final Balance balanceframe = new Balance();
    private static final Deposit depositframe = new Deposit();
    private static final Withdraw withdrawframe = new Withdraw();
    private static SecretKey encryptionKey;
    private static SecretKey macKey2;

    public static void main(String[] args) {

        loginframe.setVisible(true);
        loginframe.pack();
        loginframe.setLocationRelativeTo(null);

        //Login Screen Buttons
        javax.swing.JButton loginBtn = loginframe.getLoginBtn();
        javax.swing.JButton regBtn = loginframe.getRegBtn();

        //Options Screen Buttons
        javax.swing.JButton logoutBtn = optionsframe.getLogoutBtn();
        javax.swing.JButton withdrawBtn = optionsframe.getWithdrawBtn();
        javax.swing.JButton depositBtn = optionsframe.getDepositBtn();
        javax.swing.JButton balanceBtn = optionsframe.getBalanceBtn();

        //Deposit Screen Buttons
        javax.swing.JButton depositMoneyBtn = depositframe.getDepositBtn();
        javax.swing.JButton dHomeBtn = depositframe.getHomeBtn();
        javax.swing.JButton dLogoutBtn = depositframe.getLogoutBtn();

        //Withdraw Screen Buttons
        javax.swing.JButton withdrawMoneyBtn = withdrawframe.getWithdrawBtn();
        javax.swing.JButton wHomeBtn = withdrawframe.getHomeBtn();
        javax.swing.JButton wLogoutBtn = withdrawframe.getLogoutBtn();

        //Balance Screen Buttons
        javax.swing.JButton bHomeBtn = balanceframe.getHomeBtn();
        javax.swing.JButton bLogoutBtn = balanceframe.getLogoutBtn();

        try (Socket socket = new Socket(SERVER_ADDRESS, SERVER_PORT); PrintWriter out = new PrintWriter(socket.getOutputStream(), true); BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));) {

            System.out.println("Connected to the bank server.");
            loginBtn.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent evt) {
                    try {
                        if (loginUser(out, in)) {
                            performKeyDistributionProtocol(out, in);
                            loginframe.reset();
                            loginframe.setVisible(false);
                            optionsframe.setVisible(true);
                            optionsframe.pack();
                            optionsframe.setLocationRelativeTo(null);
                        }
                    } catch (IOException e) {
                        System.err.println("An error occurred: " + e.getMessage());
                        e.printStackTrace();
                    }
                }
            });

            regBtn.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent evt) {
                    try {
                        registerUser(out, in);
                    } catch (IOException e) {
                        System.err.println("An error occurred: " + e.getMessage());
                        e.printStackTrace();
                    }

                }
            });

            depositMoneyBtn.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent evt) {
                    try {
                        depositMoney(out, in);
                    } catch (IOException e) {
                        System.err.println("An error occurred: " + e.getMessage());
                        e.printStackTrace();
                    }

                }
            }
            );

            withdrawMoneyBtn.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent evt) {
                    try {
                        withdrawMoney(out, in);
                    } catch (IOException e) {
                        System.err.println("An error occurred: " + e.getMessage());
                        e.printStackTrace();
                    }

                }
            }
            );

            balanceBtn.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent evt) {
                    try {
                        optionsframe.setVisible(false);
                        balanceframe.setVisible(true);
                        balanceframe.pack();
                        balanceframe.setLocationRelativeTo(null);
                        getBalance(out, in);
                    } catch (IOException e) {
                        System.err.println("An error occurred: " + e.getMessage());
                        e.printStackTrace();
                    }

                }
            }
            );

            //Add actionlisteners to navigation buttons
            addNavBtn(logoutBtn, loginframe, optionsframe, 2,out);
            addNavBtn(withdrawBtn, withdrawframe, optionsframe, 0,null);
            addNavBtn(depositBtn, depositframe, optionsframe, 0, null);
            addNavBtn(dHomeBtn, optionsframe, depositframe, 1, null);
            addNavBtn(dLogoutBtn, loginframe, depositframe, 2, out);
            addNavBtn(wHomeBtn, optionsframe, withdrawframe, 1, null);
            addNavBtn(wLogoutBtn, loginframe, withdrawframe, 2, out);
            addNavBtn(bHomeBtn, optionsframe, balanceframe, 1, null);
            addNavBtn(bLogoutBtn, loginframe, balanceframe, 2, out);

            while (true) {

            }
        } catch (IOException e) {
            System.err.println("An error occurred: " + e.getMessage());
            e.printStackTrace();
        } catch (Exception e) {
            System.err.println("An error occurred: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static boolean registerUser(PrintWriter out, BufferedReader in) throws IOException {
        String username = loginframe.getUsername();
        String password = loginframe.getPassword();
        if (!username.equals("") && !password.equals("")) {
            try {
                out.println(encrypt("REGISTER",sharedKey));
                out.println(encrypt(loginframe.getUsername(), sharedKey));
                out.println(encrypt(loginframe.getPassword(), sharedKey));
            } catch (Exception e) {
                System.err.println("Decryption error: " + e.getMessage());
                e.printStackTrace();
            }
            String serverResponse = in.readLine();
            loginframe.setMsg(serverResponse, (!serverResponse.startsWith("ERROR")));

            return !serverResponse.startsWith("ERROR");
        }
        loginframe.setMsg("ERROR: Please enter a valid username and password", false);
        return false;
    }

    private static boolean loginUser(PrintWriter out, BufferedReader in) throws IOException {
        try {
            out.println(encrypt("LOGIN", sharedKey));
            out.println(encrypt(loginframe.getUsername(), sharedKey));
            out.println(encrypt(loginframe.getPassword(), sharedKey));

            String serverResponse = in.readLine();
            loginframe.setMsg(serverResponse, ("LOGGED IN".equals(serverResponse)));

            return "LOGGED IN".equals(serverResponse);
        } catch (Exception e) {
            System.err.println("Decryption error: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    private static void addNavBtn(javax.swing.JButton button, javax.swing.JFrame nextFrame, javax.swing.JFrame lastFrame, int choice, PrintWriter out) {
        button.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                switch (choice) {
                    case 1: //return to home page
                        depositframe.reset();
                        withdrawframe.reset();
                        balanceframe.reset();
                        break;
                    case 2: //logout
                        try{
                        out.println(encrypt("QUIT",encryptionKey));
                        }catch(Exception e){
                            System.err.println("Encryption error: " + e.getMessage());
                            e.printStackTrace();
                        }
                    default:
                        break;
                }
                lastFrame.setVisible(false);
                nextFrame.setVisible(true);
                nextFrame.pack();
                nextFrame.setLocationRelativeTo(null);
            }
        });
    }

    private static void depositMoney(PrintWriter out, BufferedReader in) throws IOException {
        String amount = depositframe.getAmount();
        try{
            out.println(encrypt("DEPOSIT",encryptionKey));
            out.println(encrypt(amount,encryptionKey));
        }catch(Exception e){
            System.err.println("Encryption error: " + e.getMessage());
            e.printStackTrace();
        }
        // Read the encrypted response from the server
        String encryptedResponse = in.readLine();
        String receivedMAC = in.readLine(); // Receive MAC
        System.out.println("Received encrypted deposit confirmation: " + encryptedResponse); // Print the encrypted message
        // Decrypt the response
        try {
            String decryptedResponse = decrypt(encryptedResponse, encryptionKey);

            // Verify MAC for integrity
            if (verifyMAC(encryptedResponse, receivedMAC, macKey2)) {
                depositframe.setMsg(decryptedResponse); // Display the decrypted message
            } else {
                depositframe.setMsg("Integrity check failed! Response might be tampered.");
            }

        } catch (Exception e) {
            System.err.println("Decryption error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void withdrawMoney(PrintWriter out, BufferedReader in) throws IOException {
        System.out.println("Enter amount to withdraw:");
        String amount = withdrawframe.getAmount();
        try{
            out.println(encrypt("WITHDRAW",encryptionKey));
            out.println(encrypt(amount,encryptionKey));
        }catch(Exception e){
            System.err.println("Encryption error: " + e.getMessage());
            e.printStackTrace();
        }
        // Read the encrypted response from the server
        String encryptedResponse = in.readLine();
        String receivedMAC = in.readLine(); // Receive MAC
        System.out.println("Received encrypted withdrawal confirmation: " + encryptedResponse); // Print the encrypted message
        // Decrypt the response
        try {
            String decryptedResponse = decrypt(encryptedResponse, encryptionKey);

            // Verify MAC for integrity
            if (verifyMAC(encryptedResponse, receivedMAC, macKey2)) {
                withdrawframe.setMsg(decryptedResponse); // Display the decrypted message
            } else {
                withdrawframe.setMsg("Integrity check failed! Response might be tampered.");
            }

        } catch (Exception e) {
            System.err.println("Decryption error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void getBalance(PrintWriter out, BufferedReader in) throws IOException {
        try{
        out.println(encrypt("VIEW BALANCE",encryptionKey));
        }catch(Exception e){
            System.err.println("Encryption error: " + e.getMessage());
            e.printStackTrace();
        }
        String encryptedResponse = in.readLine(); // Receive encrypted balance
        String receivedMAC = in.readLine(); // Receive MAC
        System.out.println("Received encrypted balance info: " + encryptedResponse); // For debugging
        try {
            String decryptedResponse = decrypt(encryptedResponse, encryptionKey);

            // Verify MAC for integrity
            if (verifyMAC(encryptedResponse, receivedMAC, macKey2)) {
                balanceframe.setMsg("$"+decryptedResponse); // Show decrypted message
            } else {
                balanceframe.showError();
            }

        } catch (Exception e) {
            System.err.println("Decryption error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void performKeyDistributionProtocol(PrintWriter out, BufferedReader in) throws IOException {
        try {
            // Step 1: Generate client nonce (nonce_C) and send to server
            String nonce_C = generateNonce();
            out.println(encrypt(nonce_C, sharedKey));

            // Step 2: Receive server's nonce and decrypt it
            String encryptedNonce_S = in.readLine();
            String nonce_S = decrypt(encryptedNonce_S, sharedKey);

            // Step 3: Derive Master Secret from nonces
            SecretKey masterSecret = deriveMasterSecret(nonce_C, nonce_S, sharedKey);
            System.out.println("Master Secret established.");

            // Derive Data Encryption Key and MAC Key from Master Secret
            SecretKey[] keys = deriveKeysFromMasterSecret(masterSecret);
            encryptionKey = keys[0];
            macKey2 = keys[1];
            System.out.println("Data Encryption Key and MAC Key derived.");

            // Indicate completion
            System.out.println("KEY DISTRIBUTION COMPLETE");

        } catch (Exception e) {
            throw new IOException("Key distribution failed", e);
        }
    }

    private static String generateNonce() {
        // Securely generate and return a nonce
        return Long.toString(new SecureRandom().nextLong());
    }

    private static String encrypt(String data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private static String decrypt(String data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] original = cipher.doFinal(Base64.getDecoder().decode(data));
        return new String(original);
    }

    private static SecretKey deriveMasterSecret(String nonce_C, String nonce_S, SecretKey sharedKey) throws Exception {
        // Derive Master Secret (example method, adjust as needed)
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] hash = sha256.digest((nonce_C + nonce_S).getBytes());
        return new SecretKeySpec(Arrays.copyOf(hash, 16), "AES"); // Using first 128 bits of hash
    }

    private static SecretKey[] deriveKeysFromMasterSecret(SecretKey masterSecret) throws Exception {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] hash = sha256.digest(masterSecret.getEncoded());

        // Split the hash in half; use the first part for the encryption key, the second
        // part for the MAC key
        byte[] encryptionKeyBytes = Arrays.copyOfRange(hash, 0, hash.length / 2);
        byte[] macKeyBytes = Arrays.copyOfRange(hash, hash.length / 2, hash.length);

        // Create SecretKey objects from the byte arrays
        SecretKey encryptionKey = new SecretKeySpec(encryptionKeyBytes, "AES");
        SecretKey macKey = new SecretKeySpec(macKeyBytes, MAC_ALGORITHM); // Use "HmacSHA256" for HMAC operations

        return new SecretKey[]{encryptionKey, macKey};
    }

    private static boolean verifyMAC(String data, String receivedMAC, SecretKey key) throws Exception {
        Mac mac = Mac.getInstance(MAC_ALGORITHM);
        mac.init(key);
        byte[] macBytes = mac.doFinal(data.getBytes());
        String calculatedMAC = Base64.getEncoder().encodeToString(macBytes);
        return calculatedMAC.equals(receivedMAC);
    }
}
