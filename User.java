import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.*;
import java.security.spec.KeySpec;
import java.util.*;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class User {
    private String username;
    private String passwordHash;
    private String masterPassword;
    private String userDirectory;
    private byte[] salt;

    private HashMap<String, String> securityQuestions;
    private HashMap<String, String[]> localList = new HashMap<>();

    // Create new user data
    public User(String username, String masterPassword, HashMap<String, String> securityQuestions) {
        this.username = username;
        this.salt = generateSalt();
        this.passwordHash = hashPassword(masterPassword, salt);
        this.securityQuestions = securityQuestions;
        this.masterPassword = masterPassword;
        this.userDirectory = "users/" + username;
    }

    // Load existing user data
    public User(String username, String passwordHash, byte[] salt, HashMap<String, String> securityQuestions) {
        this.username = username;
        this.passwordHash = passwordHash;
        this.securityQuestions = securityQuestions;
        this.salt = salt;
        this.userDirectory = "users/" + username;
    }

    // Takes a password and a salt and returns a secret key that is used for secure encryption
    public SecretKey getkeyFromPassword(String password, byte[] salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256"); // Factory object that makes encryption keys (algorithm)
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256); // Creates instructions on how to make the key
        SecretKey tmp = factory.generateSecret(spec); // Creates the key in a raw format
        return new SecretKeySpec(tmp.getEncoded(), "AES"); // Converts into AES format and returns it
    }   

    // Encrypts a given String
    public String encrypt(String plainText) {
        try {
            SecretKey key = getkeyFromPassword(masterPassword, salt); // Creates the encryption key
            Cipher cipher = Cipher.getInstance("AES"); // Fetches the encryption algorithm (AES)
            cipher.init(Cipher.ENCRYPT_MODE, key); // Set to encrypt mode
            byte[] encryptedBytes = cipher.doFinal(plainText.getBytes()); // Intiailize the encrypted BYTES of the password
            return Base64.getEncoder().encodeToString(encryptedBytes); // Return a string formatted encryption of the password
        } catch (Exception e) {
            System.out.println("Encryption Error: " + e.getMessage());
            return plainText;
        }
    }

    // Decrypts a given String
    public String decrypt(String encryptedtext) {
        try {
             SecretKey key = getkeyFromPassword(masterPassword, salt); // Creates the encryption key
             Cipher cipher = Cipher.getInstance("AES"); // Fetches the encryption algorithm
             cipher.init(Cipher.DECRYPT_MODE, key); // Set to decrypt mode
             byte[] encryptedBytes = Base64.getDecoder().decode(encryptedtext); // Fetch the encrypted bytes of the encrypted password
             byte[] decryptedBytes = cipher.doFinal(encryptedBytes); // Decrypt the bytes
             return new String(decryptedBytes); // Return the decrypted bytes into plain text (original password)
        } catch (Exception e) {
            System.out.println("Decryption Error: " + e.getMessage());
            return encryptedtext;
        }
    }

    // Saves a login
    public void saveLogin(String compositeKey, String loginPassword) { // These are already encrypted
        String[] itemNameAndUsername = compositeKey.split(":"); 
        localList.put(compositeKey, new String[]{itemNameAndUsername[1], loginPassword});

        // Save new login to file
        try {
            File file = new File(userDirectory + "/passwords.csv");
            file.createNewFile();
            
            BufferedWriter writer = new BufferedWriter(new FileWriter(userDirectory + "/passwords.csv", true));
            writer.write(itemNameAndUsername[0] + "," + itemNameAndUsername[1] + "," + loginPassword);
            writer.newLine();
            writer.close();
            
            System.out.println("\nLogin saved successfully");
        } catch (IOException e) {
            System.out.println("An error occurred while creating login. Please try again");
            PasswordManager.displayOptions();
        }
    }

    // Checks for a duplicate login and returns a boolean status
    public boolean checkDuplicateLogin(String itemName, String loginUsername) {
        // Read file to find duplicate logins
        try (BufferedReader reader = new BufferedReader(new FileReader(userDirectory + "/passwords.csv"))) {
            String line;

            while ((line = reader.readLine()) != null) {
                String[] login = line.split(",");
                
                if (itemName.equals(decrypt(login[0])) && loginUsername.equals(decrypt(login[1]))) { // If it finds a login that has a matching item name and username
                    return true;
                }
            }
        } catch (FileNotFoundException e) {
            // File doesn't exist yet
        } catch (IOException e) {
            System.out.println("An error occurred while checking for duplicates");
        }

        return false;
    }

    /*
    0 - Name of the Login
    1 - Username
    2 - Password
    Checks the existence of a login value (such as name, password, and username) in the logins.csv file
    */
    public boolean checkLoginExistence(int type, String value) {
        // Read file to check for login
        try (BufferedReader reader = new BufferedReader(new FileReader(userDirectory + "/passwords.csv"))) {
            String line;

            while ((line = reader.readLine()) != null) {
                String login[] = line.split(",");

                if (decrypt(login[type]).equals(value)) { // Decrypt login and see if it matches
                    return true;
                }
            }
        } catch (FileNotFoundException e) {
            // File doesn't exist yet
            return false;
        } catch (IOException e) {
            System.out.println("An error occurred while checking login. Please try again");
        }   

        return false;
    }

    // Find a login by item and name, then return the entire login entry
    public Map.Entry<String, String[]> findLogin(String itemName, String username) {
        String encryptedItemName = encrypt(itemName);
        String encryptedUserName = encrypt(username);

        for (Map.Entry<String, String[]> entry : localList.entrySet()) {
            String keyParts[] = entry.getKey().split(":");

            if (encryptedItemName.equals(keyParts[0]) && encryptedUserName.equals(keyParts[1])) {
                return entry;
            }
        }

        return null;
    }

    // Delete a login by its item name and username
    public void deleteLogin(String itemName, String username) {
        localList.remove(encrypt(itemName) + ":" + encrypt(username));

        try {
            BufferedReader reader = new BufferedReader(new FileReader(userDirectory + "/passwords.csv"));
            ArrayList<String> lines = new ArrayList<>();
            String line;

            while ((line = reader.readLine()) != null) {
                String[] credentials = line.split(",");
                String decItemName = decrypt(credentials[0]);
                String decUsername = decrypt(credentials[1]);

                if (!(itemName.equals(decItemName) && username.equals(decUsername))) {
                    lines.add(line);
                }
            }

            reader.close();

            BufferedWriter writer = new BufferedWriter(new FileWriter(userDirectory + "/passwords.csv"));
            
            for (String writeLine : lines) {
                writer.write(writeLine);
                writer.newLine();
            }

            writer.close();
        } catch (IOException e) {
            System.out.println("An error occurred while deleting login. Please try again");
            PasswordManager.displayOptions();
        }
    }

    // Update a login
    public void updateLogin(String oldItemName, String oldUsername, String newItemName, String newUsername, String newPassword) {
        try {
            // Read all logins except the one we're updating
            ArrayList<String> lines = new ArrayList<>();
            BufferedReader reader = new BufferedReader(
                new FileReader(userDirectory + "/passwords.csv")
            );
            String line;
            
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(",");
                String decItem = decrypt(parts[0]);
                String decUser = decrypt(parts[1]);
                
                // Skip the old login
                if (decItem.equals(oldItemName) && decUser.equals(oldUsername)) {
                    continue;
                }
                
                lines.add(line);
            }
            reader.close();
            
            // Add the updated login
            String encryptedItem = encrypt(newItemName);
            String encryptedUsername = encrypt(newUsername);
            String encryptedPassword = encrypt(newPassword);
            lines.add(encryptedItem + "," + encryptedUsername + "," + encryptedPassword);
            
            // Rewrite everything
            BufferedWriter writer = new BufferedWriter(new FileWriter(userDirectory + "/passwords.csv"));

            for (String l : lines) {
                writer.write(l);
                writer.newLine();
            }
            writer.close();
            
            // Update local hashmap
            String oldKey = encrypt(oldItemName) + ":" + encrypt(oldUsername);
            localList.remove(oldKey);
            
            String newKey = encryptedItem + ":" + encryptedUsername;
            localList.put(newKey, new String[]{encryptedUsername, encryptedPassword});
            
            System.out.println("\nLogin updated successfully");
        } catch (IOException e) {
            System.out.println("Error updating login: " + e.getMessage());
        }
    }

    // One way password hash
    private String hashPassword(String password, byte[] salt) {
        try {
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] hash = factory.generateSecret(spec).getEncoded();
            
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException("Error hashing password", e);
        }
    }

    // Randomly generate a salt
    public static byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] newSalt = new byte[16];
        random.nextBytes(newSalt);

        return newSalt;
    }

    // Getters
    public String getUsername() { return this.username; }
    public String getPasswordHash() { return this.passwordHash; }
    public byte[] getSalt() { return this.salt; }
    public HashMap<String, String[]> getLocalList() { return this.localList; }

    public boolean checkPassword(String enteredPassword) {
        String hashedPassword = hashPassword(enteredPassword, this.salt);

        return hashedPassword.equals(this.passwordHash);
    }

    public boolean checkSecurityQuestion(String question, String answer) {
        if (!securityQuestions.containsKey(question)) {
            return false;
        }

        return securityQuestions.get(question).equalsIgnoreCase(answer);
    }

    public Set<String> getSecurityQuestions() {
        return securityQuestions.keySet();
    }

    public String getSecurityAnswer(String question) {
        try (BufferedReader reader = new BufferedReader(new FileReader(userDirectory + "/credentials.csv"))) {
            String line;

            while ((line = reader.readLine()) != null) {
                String[] questionAndAnswer = line.split(",");

                if (questionAndAnswer[0].equals(question)) {
                    return questionAndAnswer[1];
                }
            }
        } catch (IOException e) {
            System.out.println("An error occurred while changing your security questions. Please try again");
            PasswordManager.changeSecurityQuestions();
        }

        return null;
    }

    // Load the user's credentials and security questions
    public static User loadFromFile(String username) { // Loads and returns a user object given the user's folder
        try (BufferedReader reader = new BufferedReader(new FileReader("users/" + username + "/credentials.csv"))) {
            String line;
            int i = 0;

            String loginUsername = "";
            String loginPassword = "";
            byte[] loginSalt = null;
            HashMap<String, String> securityQuestions = new HashMap<>();

            // Read each line and retrieve the credentials
            while ((line = reader.readLine()) != null) {
                String splitList[] = line.split(",");

                if (i == 0) { // Username, Master Password, Salt
                    loginUsername = splitList[0];
                    loginPassword = splitList[1];
                    loginSalt = Base64.getDecoder().decode(splitList[2]);
                } else {
                    securityQuestions.put(splitList[0], splitList[1]);
                }

                i++;
            }

            // Return new user object with the credentials
            return new User(loginUsername, loginPassword, loginSalt, securityQuestions);  
        } catch (IOException e) {
            System.out.println("An error occurred while loading user: " + username);
            return null;
        }
    }

    // Load the user's logins
    public void loadLogins() {
        try (BufferedReader reader = new BufferedReader(new FileReader(userDirectory + "/passwords.csv"))) {
            String line;

            while ((line = reader.readLine()) != null) {
                String[] currentLogin = line.split(",");

                localList.put(currentLogin[0] + ":" + currentLogin[1], new String[]{currentLogin[1], currentLogin[2]});
            }
        } catch (FileNotFoundException e) {
            // No logins yet
        } catch (IOException e) {
            System.out.println("An error occurred while loading your Logins. Please reopen the application and try again");
            System.exit(1);
        }
    }

    // Saves credentials to a file
    public void saveCredentials() {
        File dir = new File(userDirectory);

        if (!dir.exists()) {
            dir.mkdirs();
        }

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(userDirectory + "/credentials.csv"))) {
            writer.write(username + "," + passwordHash + "," + Base64.getEncoder().encodeToString(salt));
            writer.newLine();

            for (Map.Entry<String, String> entry : securityQuestions.entrySet()) {
                writer.write(entry.getKey() + "," + entry.getValue());
                writer.newLine();
            }
        } catch (IOException e) {
            System.out.println("An error occurred while saving your credentials. Please reopen the application and try again");
            System.exit(1);
        }
    }

    // Setters
    public void changePassword(String newPassword) {
        this.passwordHash = hashPassword(newPassword, this.salt);

        try { // Replace the master password in the accountsCredentials.csv file with the new one
            ArrayList<String> lineList = new ArrayList<>();
            BufferedReader reader = new BufferedReader(new FileReader(userDirectory + "/credentials.csv"));
            String line;

            // Read the file and store it all into an arraylist
            while ((line = reader.readLine()) != null) {
                lineList.add(line);
            }
            reader.close();

            // Modify the master password in the arraylist
            lineList.set(0, username + "," + this.passwordHash + "," + Base64.getEncoder().encodeToString(salt));

            // Rewrite everything back into the file with the new password
            BufferedWriter writer = new BufferedWriter(new FileWriter(userDirectory + "/credentials.csv"));
            for (String i : lineList) {
                writer.write(i);
                writer.newLine();
            }
            writer.close();

            masterPassword = newPassword;
            System.out.println("Master Password changed successfully!");
        } catch (IOException e) {
            System.out.println("An error occurred while changing your Master Password. Please try again");
        }
    }

    public void changeUsername(String newUsername) {
        this.username = newUsername;

        try { // Replace the username in the credentials.csv file with the new one
            ArrayList<String> lineList = new ArrayList<>();
            BufferedReader reader = new BufferedReader(new FileReader(userDirectory + "/credentials.csv"));
            String line;
            
            // Read the file and store it all into an arraylist
            while ((line = reader.readLine()) != null) {
                lineList.add(line);
            }
            reader.close();

            // Modify the master password in the arraylist
            lineList.set(0, newUsername + "," + passwordHash + "," + Base64.getEncoder().encodeToString(salt));

            // Rewrite everything back into the file with the new password
            BufferedWriter writer = new BufferedWriter(new FileWriter(userDirectory + "/credentials.csv"));
            for (String i : lineList) {
                writer.write(i);
                writer.newLine();
            }
            writer.close();

            username = newUsername;

            File oldDir = new File(userDirectory);
            oldDir.renameTo(new File("users/" + newUsername));

            System.out.println("Username changed successfully!");
        } catch (IOException e) {
            System.out.println("An error occurred while changing your Username. Please try again");
        }
    }

    public void changeSecurityAnswer(String question, String newAnswer) {
        try { // Replace the security question answers in the credentials.csv file with new ones
            BufferedReader reader = new BufferedReader(new FileReader(userDirectory + "/credentials.csv"));
            ArrayList<String> lineList = new ArrayList<>();
            String line;
            int i = 0;
            
            // Read through the file and store to an arraylist
            while ((line = reader.readLine()) != null) {
                String[] questionAndAnswer = line.split(",");

                if (questionAndAnswer[0].equals(question)) {
                    // Modify the security question answers with new ones
                    lineList.add(questionAndAnswer[0] + "," + newAnswer);
                } else {
                    lineList.add(line);
                }
                
                i++;
            }

            reader.close();

            // Rewrite the file with new answers
            BufferedWriter writer = new BufferedWriter(new FileWriter(userDirectory + "/credentials.csv"));
            for (String i2 : lineList) {
                writer.write(i2);
                writer.newLine();
            }

            writer.close();
        } catch (IOException e) {
            System.out.println("An error occurred while changing your Security Questions. Please try again");
            PasswordManager.settingsPage(true);
        }
    }

    public void setMasterPassword(String masterPassword) { // This stores master password in memory
        this.masterPassword = masterPassword;
    }
}