import java.io.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class PasswordManager {
    // Global Variables
    public static Scanner sc = new Scanner(System.in);

    public static HashMap<String, String[]> localList = new HashMap<>(); // Save encrypted passwords in session for easy retrieval
    public static String username;
    public static String masterPassword;
    public static byte[] salt; // Random salt generated when the user first created their account based off their master password

    // File Paths
    public static String accountCredentials = "credentials.csv";
    public static String loginsFile = "logins.csv";

    /*
    Takes a password and a salt
    Returns a secret key that is used for secure encryption
    */
    public static SecretKey getkeyFromPassword(String password, byte[] salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256"); // Factory object that makes encryption keys (algorithm)
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256); // Creates instructions on how to make the key
        SecretKey tmp = factory.generateSecret(spec); // Creates the key in a raw format
        return new SecretKeySpec(tmp.getEncoded(), "AES"); // Converts into AES format and returns it
    }   
    
    /*
    Displays the page to sign into the user's account
    */
    public static void loginPage() {
        System.out.println("\n====LOGIN====");
        System.out.println("Forgot Password? Enter \"/resetpassword\"");

        System.out.print("Username: ");
        username = sc.nextLine();

        if (username.equalsIgnoreCase("/resetpassword")) {
            resetPassword();
            return;
        }

        System.out.print("Master Password: ");
        masterPassword = sc.nextLine();

        if (masterPassword.equalsIgnoreCase("/resetpassword")) {
            resetPassword();
            return;
        }

        // Read the accountCredentials.csv file
        try (BufferedReader reader = new BufferedReader(new FileReader(accountCredentials))) {
            String[] credentials = reader.readLine().split(",");

            // Make sure the user entered the correct username and password
            if (username.equals(credentials[0]) && masterPassword.equals(credentials[1])) {
                salt = Base64.getDecoder().decode(credentials[2]); // Decode the salt using the master password
                System.out.println("Login Successful");
                displayOptions();
            } else {
                System.out.println("Incorrect Login Details");
                loginPage();
            }
        } catch (IOException e) {
            System.out.println("An error occurred while logging in. Please try again");
            loginPage();
        }
    }

    /*
    Encrypts a given String
     */
    public static String encrypt(String plainText) {
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

    /*
    Decrypts a given String
     */
    public static String decrypt(String encryptedtext) {
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

    /*
    Displays the page for changing the master password
    */
    public static void passwordChange() {
        System.out.print("\nEnter New Password: ");
        String newPassword = sc.nextLine();

        if (newPassword.equalsIgnoreCase("/resetpassword")) {
            System.out.println("This Master Password is unuseable. Try something else");
            passwordChange();
            return;
        } else if (newPassword.length() < 8 || newPassword.length() > 60) { // Check password length
            System.out.println("Your Master Password must be between 8-60 characters");
            passwordChange();
            return;
        }

        System.out.print("Confirm Password: ");
        String confirmedPassword = sc.nextLine();

        if (!newPassword.equals(confirmedPassword)) {
            System.out.println("Passwords did not match");
            passwordChange();
        } else {
            try { // Replace the master password in the accountsCredentials.csv file with the new one
                ArrayList<String> lineList = new ArrayList<>();
                BufferedReader reader = new BufferedReader(new FileReader(accountCredentials));
                String line;

                // Read the file and store it all into an arraylist
                while ((line = reader.readLine()) != null) {
                    lineList.add(line);
                }
                reader.close();

                // Modify the master password in the arraylist
                lineList.set(0, username + "," + newPassword + "," + Base64.getEncoder().encodeToString(salt));

                // Rewrite everything back into the file with the new password
                BufferedWriter writer = new BufferedWriter(new FileWriter(accountCredentials));
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
    }

    /*
    Displays the page for changing the username
    */
    public static void usernameChange() {
        System.out.print("\nEnter New Username: ");
        String newUsername = sc.nextLine();

        if (newUsername.equalsIgnoreCase("/resetpassword")) {
            System.out.println("This Username is unuseable. Try something else");
            usernameChange();
            return;
        } else if (newUsername.length() == 0 || newUsername.length() > 15) { // Check username length
            System.out.println("Your Username must be between 1-15 characters");
            usernameChange();
            return;
        }

        try { // Replace the username in the accountsCredentials.csv file with the new one
            ArrayList<String> lineList = new ArrayList<>();
            BufferedReader reader = new BufferedReader(new FileReader(accountCredentials));
            String line;

            // Read the file and store it all into an arraylist
            while ((line = reader.readLine()) != null) {
                lineList.add(line);
            }
            reader.close();

            // Modify the master password in the arraylist
            lineList.set(0, newUsername + "," + masterPassword + "," + Base64.getEncoder().encodeToString(salt));

            // Rewrite everything back into the file with the new password
            BufferedWriter writer = new BufferedWriter(new FileWriter(accountCredentials));
            for (String i : lineList) {
                writer.write(i);
                writer.newLine();
            }
            writer.close();

            username = newUsername;
            System.out.println("Username changed successfully!");
        } catch (IOException e) {
            System.out.println("An error occurred while changing your Username. Please try again");
        }
    }

    /*
    Opens the security questions page to reset the user's master password
    */
    public static void resetPassword() {
        System.out.println("\n====PASSWORD RESET====");
        System.out.println("Answer the following security questions to reset your Master Password");

        // Read the accountCredentials.csv file and retrieve security questions
        try (BufferedReader reader = new BufferedReader(new FileReader(accountCredentials))) {
            String line;
            int i = 1;

            line = reader.readLine();
            if (line != null) {
                String[] credentials = line.split(",");
                username = credentials[0];
                masterPassword = credentials[1];
                salt = Base64.getDecoder().decode(credentials[2]);
            }

            // Ask each security question
            while ((line = reader.readLine()) != null) {
                if (i == 1 || i == 2) {
                    String questionAndAnswer[] = line.split(",");

                    System.out.print("\n" + questionAndAnswer[0] + ": ");
                    String answer = sc.nextLine();

                    if (!answer.equalsIgnoreCase(questionAndAnswer[1])) { // Incorrect answer, exit user back out to the login page
                        System.out.println("Incorrect Answer");
                        loginPage();
                        return;
                    }
                }

                i++;
            }

            passwordChange();
        } catch (IOException e) {
            System.out.println("An error occurred while retrieving security questions");
        }
    }

    /*
    Displays the page to create an account
    */
    public static void accountCreation() { 
        System.out.println("\nIt seems like this is your first time using the Password Manager");
        System.out.println("Let's create your account");

        System.out.print("\nUsername: ");
        username = sc.nextLine();

        if (username.equalsIgnoreCase("/resetpassword")) {
            System.out.println("This Username is unuseable. Try something else");
            accountCreation();
            return;
        } else if (username.length() == 0 || username.length() > 15) { // Check username length
            System.out.println("Your Username must be between 1-15 characters");
            accountCreation();
            return;
        }

        System.out.print("Master Password: ");
        masterPassword = sc.nextLine();
        
        if (masterPassword.equalsIgnoreCase("/resetpassword")) {
            System.out.println("This Master Password is unuseable. Try something else");
            accountCreation();
            return;
        } else if (masterPassword.length() < 8 || masterPassword.length() > 60) { // Check password length
            System.out.println("Your Master Password must be between 8-60 characters");
            accountCreation();
            return;
        }

        // Use a secure randomness algorithm to generate a salt for encryption
        SecureRandom random = new SecureRandom();
        salt = new byte[16];
        random.nextBytes(salt);

        System.out.println("\nNow let's configure some security questions in case you forget your password");
        
        String question1 = "What city were you born in?";
        System.out.println("\n" + question1);
        String cityOfBirth = sc.nextLine();

        if (cityOfBirth.length() == 0 || cityOfBirth.length() > 128) { // Check length of security question answers
            System.out.println("The length of your answer must be between 1-128 characters");
            accountCreation();
            return;
        }
        
        String question2 = "In what city did your parents meet?";
        System.out.println("\n" + question2);
        String cityParentsMeet = sc.nextLine();

        if (cityParentsMeet.length() == 0 || cityParentsMeet.length() > 128) { // Check length of security question answers
            System.out.println("The length of your answer must be between 1-128 characters");
            accountCreation();
            return;
        }

        // Write credentials to a new file
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(accountCredentials))) {
            writer.write(username + "," + masterPassword + "," + Base64.getEncoder().encodeToString(salt));
            writer.write("\n" + question1 + "," + cityOfBirth);
            writer.write("\n" + question2 + "," + cityParentsMeet);
        } catch (IOException e) {
            System.out.println("An error while creating your account. Please try again");
            createLogin();
        }
    }

    /*
    Displays the settings page for configuration
    */
    public static void settingsPage(boolean bypassCheck) {
        if (!bypassCheck) { // If this method is not called explicitly to not check the user's credentials then user must re-enter mastesr password
            System.out.print("Enter your Master Password to modify account settings: ");
            String input = sc.nextLine();
            
            if (!input.equals(masterPassword)) {
                System.out.println("Incorrect Login Details");
                displayOptions();
                return;
            }
        }

        System.out.println("\n====SETTINGS====");
        System.out.println("1: Change Master Password");
        System.out.println("2: Change Username");
        System.out.println("3: Change Security Questions");
        System.out.println("\nEnter any other key to exit settings");

        System.out.print("Option: ");
        String option = sc.nextLine();

        switch (option) {
            case "1": // Change master password
                passwordChange();
                break;
            case "2": // Change username
                usernameChange();
                break;
            case "3": // Change security questions
                changeSecurityQuestions();
                break;
        }

        displayOptions();
    }

    /*
    Displays the page for changing security questions
    */
    public static void changeSecurityQuestions() {
        try { // Replace the security question answers in the accountCredentials.csv file with new ones
            BufferedReader reader = new BufferedReader(new FileReader(accountCredentials));
            ArrayList<String> lineList = new ArrayList<>();
            String line;
            int i = 0;
            boolean validInput = true;
            
            // Read through the file and store to an arraylist
            while ((line = reader.readLine()) != null) {
                lineList.add(line);

                if (i == 1 || i == 2) { // Prompt user to change answers
                    String[] questionAndAnswer = line.split(",");
                    System.out.println("\n" + questionAndAnswer[0]);
                    System.out.println("Your Answer: \"" + questionAndAnswer[1] + "\"");

                    System.out.print("Change to: ");
                    String newAnswer = sc.nextLine();

                    if (newAnswer.length() == 0 || newAnswer.length() > 128) { // Check length of security question answers
                        System.out.println("The length of your answer must be between 1-128 characters");
                        validInput = false;
                        break;
                    }

                    // Modify the security question answers with new ones
                    lineList.set(i, questionAndAnswer[0] + "," + newAnswer);
                }

                i++;
            }

            reader.close();

            if (!validInput) { // If there was an invalid input exit the user to try again
                settingsPage(validInput);
                return;
            }

            // Rewrite the file with new answers
            BufferedWriter writer = new BufferedWriter(new FileWriter(accountCredentials));
            for (String i2 : lineList) {
                writer.write(i2);
                writer.newLine();
            }

            writer.close();
        } catch (IOException e) {
            System.out.println("An error occurred while changing your Security Questions. Please try again");
            settingsPage(true);
        }
    }

    /*
    Pulls encrypted logins from file to an array and setups an initial environment
    */
    public static void pullLogins() {
        // Read the logins.csv file and retrieve logins
        try (BufferedReader reader = new BufferedReader(new FileReader(loginsFile))) {
            String line;

            // Store each login into a HashMap for fast and easy retrieval
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(",");

                String itemName = parts[0];
                String loginUsername = parts[1];
                String loginPassword = parts[2];

                String compositeKey = itemName + ":" + loginUsername;
                localList.put(compositeKey, new String[]{loginUsername, loginPassword});
            }
        } catch (FileNotFoundException e) {
            // File doesn't exist yet (first time user)
        } catch (IOException e) {
            System.out.println("An error occurred while retrieving account information. Please try again");
        }
    }
    
    /*
    Displays all login credentials
    */
    public static void createLogin() {
        System.out.println("\n====NEW LOGIN====");

        System.out.print("Website/Item Name: ");
        String itemName = sc.nextLine();

        System.out.print("Username: ");
        String loginUsername = sc.nextLine();

        System.out.print("Password: ");
        String loginPassword = sc.nextLine();

        if (checkDuplicateLogin(itemName, loginUsername)) { // User cannot have duplicate usernames under the same item name
            System.out.println("You cannot have duplicate usernames for the login name");
            displayOptions();
            return;
        }

        // Encrypt login information
        String encryptedItem = encrypt(itemName);
        String encryptedUsername = encrypt(loginUsername);
        String encryptedPassword = encrypt(loginPassword);

        String compositeKey = encryptedItem + ":" + encryptedUsername;
        
        // Save new login to HashMap
        localList.put(compositeKey, new String[]{encryptedUsername, encryptedPassword});

        // Save new login to file
        try {
            File file = new File(loginsFile);
            file.createNewFile();
            
            BufferedWriter writer = new BufferedWriter(new FileWriter(loginsFile, true));
            writer.write(encryptedItem + "," + encryptedUsername + "," + encryptedPassword);
            writer.newLine();
            writer.close();
            
            System.out.println("\nLogin saved successfully");
        } catch (IOException e) {
            System.out.println("An error occurred while creating login. Please try again");
        }

        displayOptions();
    }

    /*
    Checks for a duplicate login and returns a boolean status
    */
    public static boolean checkDuplicateLogin(String itemName, String loginUsername) {
        // Read file to find duplicate logins
        try (BufferedReader reader = new BufferedReader(new FileReader(loginsFile))) {
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
    public static boolean checkLoginExistence(int type, String value) {
        // Read file to check for login
        try (BufferedReader reader = new BufferedReader(new FileReader(loginsFile))) {
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

    /*
    Displays page for searching logins and to modify them (delete/change)
    */
    public static void modifyLogin() {
        if (localList.isEmpty()) { // If there are no logins found exit out
            System.out.println("\nNo logins saved yet");
            displayOptions();
            return;
        }

        System.out.print("\nEnter the Login Name you wish to modify: ");
        String itemName = sc.nextLine();

        if (!checkLoginExistence(0, itemName)) { // The searched login does not exist
            System.out.println("Could not find \"" + itemName + "\"");
            displayOptions();
            return;
        }

        System.out.print("Enter the Username for this login: ");
        String loginUsername = sc.nextLine();
        
        String targetKey = null;
        String[] targetValue = null;
        
        // Assign and search for the key (item name) and value (username, password)
        for (Map.Entry<String, String[]> entry : localList.entrySet()) {
            String[] keyParts = entry.getKey().split(":");
            String decryptedItem = decrypt(keyParts[0]);
            String decryptedUser = decrypt(keyParts[1]);
            
            if (decryptedItem.equals(itemName) && decryptedUser.equals(loginUsername)) {
                targetKey = entry.getKey();
                targetValue = entry.getValue();
                break;
            }
        }

        if (targetKey == null) { // If target key does not exist, exit the user
            System.out.println("Username not found under " + itemName);
            displayOptions();
            return;
        }

        System.out.println("\n(1) Item Name: " + itemName);
        System.out.println("(2) Username: " + loginUsername);
        System.out.println("(3) Password: " + decrypt(targetValue[1]));
        System.out.println("(4) Delete Login");

        System.out.print("\nWhat would you like to do (1-4): ");
        int input;

        try { // Error handling for if the user inputs a non-integer
            input = sc.nextInt();
            sc.nextLine();
        } catch (InputMismatchException e) {
            System.out.println("Enter a valid option from 1-4");
            sc.nextLine();
            displayOptions();
            return;
        }

        String newItemName = itemName;
        String newUsername = loginUsername;
        String newPassword = decrypt(targetValue[1]);

        switch (input) {
            case 1: // Change item name
                System.out.print("New Item Name: ");
                newItemName = sc.nextLine();
                break;
            case 2: // Change username
                System.out.print("New Username: ");
                newUsername = sc.nextLine();
                break;
            case 3: // Change password
                System.out.print("New Password: ");
                newPassword = sc.nextLine();
                break;
            case 4: // Delete login
                try { // Read file and removve the specific login
                    ArrayList<String> lines = new ArrayList<>();
                    BufferedReader reader = new BufferedReader(new FileReader(loginsFile));
                    String line;

                    // Look for the login
                    while ((line = reader.readLine()) != null) {
                        String[] parts = line.split(",");
                        String decItem = decrypt(parts[0]);
                        String decUser = decrypt(parts[1]);

                        if (!decItem.equals(itemName) && !decUser.equals(loginUsername)) { // Add everything back except for the removed login
                            lines.add(line);
                        }
                    }
                    reader.close();

                    BufferedWriter writer = new BufferedWriter(new FileWriter(loginsFile));

                    // Rewrite the file
                    for (String l : lines) {
                        writer.write(l);
                        writer.newLine();
                    }
                    writer.close();
                    
                    localList.remove(targetKey);

                    System.out.println("\nLogin deleted successfully");

                } catch (IOException e) {
                    System.out.println("An error occurred while deleting the login. Please try again");
                }
                displayOptions();
                return;
            default:
                System.out.println("Invalid option");
                displayOptions();
                return;
        }
        
        try { // Make changes to file according to user's request
            ArrayList<String> lines = new ArrayList<>();
            BufferedReader reader = new BufferedReader(new FileReader(loginsFile));
            String line;

            // Read file and store to an arraylist
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(",");
                String decItem = decrypt(parts[0]);
                String decUser = decrypt(parts[1]);

                if (decItem.equals(itemName) && decUser.equals(loginUsername)) {
                    lines.add(encrypt(newItemName) + "," + encrypt(newUsername) + "," + encrypt(newPassword));
                } else {
                    lines.add(line);
                }
            }
            reader.close();
            
            BufferedWriter writer = new BufferedWriter(new FileWriter(loginsFile));

            // Rewrite the file with the changes
            for (String l : lines) {
                writer.write(l);
                writer.newLine();
            }
            writer.close();
            
            localList.remove(targetKey);
            String newKey = encrypt(newItemName) + ":" + encrypt(newUsername);
            localList.put(newKey, new String[]{encrypt(newUsername), encrypt(newPassword)});

            System.out.println("\nLogin updated successfully");

        } catch (IOException e) {
            System.out.println("An error occurred while modifying the login. Please try again");
        }

        displayOptions();
    }

    /*
    Displays all login credentials
    */
    public static void viewLogins() {
        if (localList.isEmpty()) { // Exit user if user has no logins
            System.out.println("\nNo logins saved yet");
            displayOptions();
            return;
        }

        System.out.println("\n====YOUR LOGINS====");
        
        // Keep track of the number of logins
        int count = 1;

        // Print out each login
        for (Map.Entry<String, String[]> entry : localList.entrySet()) {
            String[] keyParts = entry.getKey().split(":");
            String encryptedItemName = keyParts[0];
            String encryptedUsername = keyParts[1];
            
            String itemName = decrypt(encryptedItemName);
            String username = decrypt(encryptedUsername);
            String password = decrypt(entry.getValue()[1]);
            
            System.out.println((count == 1 ? "" : "\n") + count + ". " + itemName);
            System.out.println("   Username: " + username);
            System.out.println("   Password: " + password);
            
            count++;
        }

        displayOptions();
    }
    
    /*
    Generates a random password baseed on given length
    */
    public static String generatePassword(int length) {
        // List out possible characters to scramble
        String possibleCharacters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
        // Use SecureRandom over regular random for security and better spontaneity
        SecureRandom random = new SecureRandom();
        // Use stringbuilder to compile the random password
        StringBuilder password = new StringBuilder();

        // Generate the random password using the set of characters
        for (int i = 0; i < length; i++) {
            int index = random.nextInt(possibleCharacters.length());
            password.append(possibleCharacters.charAt(index));
        }

        return password.toString();
    }

    /*
    Displays the page for generating passwords
    */
    public static void passwordGenerator() {
        System.out.println("\n====PASSWORD GENERATOR====");
        int charAmount;
        
        try { // Error handling for if the user inputs a non-integer
            System.out.print("How many characters (8-32): ");
            charAmount = sc.nextInt();
            sc.nextLine();
            
            if (charAmount >= 8 && charAmount <= 32) { // Generation limits
                System.out.println("\nGenerated Password: " + generatePassword(charAmount));
            } else {
                System.out.println("Please enter a number from 8 and 32");
            }
        } catch (InputMismatchException e) {
            System.out.println("Please enter a number from 8 and 32");
            sc.nextLine();
        }

        displayOptions();
    }

    /*
    Displays options for the user to choose from
    */
    public static void displayOptions() {
        System.out.println("\n====MENU====");
        System.out.println("1: View Logins");
        System.out.println("2: Create New Login");
        System.out.println("3: Modify a Login");
        System.out.println("4: Generate Passwords");
        System.out.println("5: Settings");
        System.out.println("\nEnter any other key to logout");

        System.out.print("\nOption: ");
        String userOption = sc.nextLine();

        switch (userOption) {
            case "1":
                 viewLogins();
                break;
            case "2":
                createLogin();
                break;
            case "3":
                modifyLogin();
                break;
            case "4":
                passwordGenerator();
                break;
            case "5":
                settingsPage(false);
                break;
        }
    }
    
    public static void main(String[] args) {
        System.out.println("====PASSWORD MANAGER====");
        System.out.println("This program manages and saves your online credentials");
        
        while (true) {
            try {
                System.out.println("\n1: Login");
                System.out.println("2: Create New Account");
                System.out.println("3: Close Application");

                System.out.print("\nOption: ");
                int input = sc.nextInt();

                if (input == 1) {
                    loginPage();
                    break;
                } else if (input == 2) {
                    accountCreation();
                    break;
                } else if (input == 3) {
                    break;
                } else {
                    System.out.println("Choose an option (number) from 1-2");
                    sc.nextLine();
                }
            } catch (InputMismatchException e) {
                System.out.println("Choose an option (number) from 1-2");
                sc.nextLine();
            }
        }

        sc.close();
    }
}