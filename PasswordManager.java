import java.io.*;
import java.security.*;
import java.util.*;

public class PasswordManager {
    // Global Variables
    public static Scanner sc = new Scanner(System.in);
    public static User currentUser = null;
    public static ArrayList<User> allUsers = new ArrayList<>();
    
    /*
    Displays the page to sign into the user's account
    */
    public static void loginPage() {
        System.out.println("\n====LOGIN====");
        System.out.println("Forgot Password? Enter \"/resetpassword\"");

        System.out.print("Username: ");
        String username = sc.nextLine();

        if (username.equalsIgnoreCase("/resetpassword")) {
            resetPassword();
            return;
        }

        System.out.print("Master Password: ");
        String masterPassword = sc.nextLine();

        if (masterPassword.equalsIgnoreCase("/resetpassword")) {
            resetPassword();
            return;
        }

        User user = findUser(username);

        if (user == null) {
            System.out.println("This account does not exist");
            loginPage();
            return;
        }

        // Make sure the user entered the correct username and password
        if (user.checkPassword(masterPassword)) {
            currentUser = user;
            currentUser.setMasterPassword(masterPassword);
            currentUser.loadLogins();

            System.out.println("Login Successful");
            displayOptions();
        } else {
            System.out.println("Incorrect Login Details");
            loginPage();
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
            currentUser.changePassword(newPassword);
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
        } else if (findUser(newUsername) != null) {
            System.out.println("This username is already taken. Try something else");
        } else if (newUsername.length() == 0 || newUsername.length() > 15) { // Check username length
            System.out.println("Your Username must be between 1-15 characters");
            usernameChange();
            return;
        }

        currentUser.changeUsername(newUsername);
    }

    /*
    Opens the security questions page to reset the user's master password
    */
    public static void resetPassword() {
        System.out.println("\n====PASSWORD RESET====");

        System.out.print("Enter your username: ");
        String username = sc.nextLine();
        User user = findUser(username);

        if (user == null) {
            System.out.println("Username not found");
            loginPage();
            return;
        }

        System.out.println("Answer the following security questions to reset your Master Password");
        Set<String> securityQuestions = user.getSecurityQuestions();

        for (String question : securityQuestions) {
            System.out.print("\n" + question + ": ");
            String answer = sc.nextLine();

            if (!user.checkSecurityQuestion(question, answer)) { // Incorrect answer, exit user back out to the login page
                System.out.println("Incorrect Answer");
                loginPage();
                return;
            }
        }

        currentUser = user;
        passwordChange();
        loginPage();
    }

    /*
    Displays the page to create an account
    */
    public static void accountCreation() { 
        System.out.println("\n=====CREATE ACCOUNT====");
        System.out.print("Username: ");
        String username = sc.nextLine();

        if (username.equalsIgnoreCase("/resetpassword")) {
            System.out.println("This Username is unuseable. Try something else");
            accountCreation();
            return;
        } else if (findUser(username) != null) {
            System.out.println("This username is already taken. Try something else");
        } else if (username.length() == 0 || username.length() > 15) { // Check username length
            System.out.println("Your Username must be between 1-15 characters");
            accountCreation();
            return;
        }

        System.out.print("Master Password: ");
        String masterPassword = sc.nextLine();
        
        if (masterPassword.equalsIgnoreCase("/resetpassword")) {
            System.out.println("This Master Password is unuseable. Try something else");
            accountCreation();
            return;
        } else if (masterPassword.length() < 8 || masterPassword.length() > 60) { // Check password length
            System.out.println("Your Master Password must be between 8-60 characters");
            accountCreation();
            return;
        }

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

        HashMap<String, String> securityQuestions = new HashMap<>();
        securityQuestions.put("What city were you born in?", cityOfBirth);
        securityQuestions.put("In what city did your parents meet?", cityParentsMeet);

        currentUser = new User(username, masterPassword, securityQuestions);
        currentUser.saveCredentials();
        allUsers.add(currentUser);

        displayOptions();
    }

    /*
    Displays the settings page for configuration
    */
    public static void settingsPage(boolean bypassCheck) {
        if (!bypassCheck) { // If this method is not called explicitly to not check the user's credentials then user must re-enter mastesr password
            System.out.print("Enter your Master Password to modify account settings: ");
            String input = sc.nextLine();
            
            if (!currentUser.checkPassword(input)) {
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
        Set<String> securityQuestions = currentUser.getSecurityQuestions();
        
        for (String question : securityQuestions) {
            System.out.println("\n" + question);
            System.out.println("Your Answer: \"" + currentUser.getSecurityAnswer(question) + "\"");

            System.out.print("Change to: ");
            String newAnswer = sc.nextLine();

            if (newAnswer.length() == 0 || newAnswer.length() > 128) { // Check length of security question answers
                System.out.println("The length of your answer must be between 1-128 characters");
                changeSecurityQuestions();
                return;
            } else {
                currentUser.changeSecurityAnswer(question, newAnswer);
            }
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

        if (currentUser.checkDuplicateLogin(itemName, loginUsername)) { // User cannot have duplicate usernames under the same item name
            System.out.println("You cannot have duplicate usernames for the login name");
            displayOptions();
            return;
        }

        // Encrypt login information
        String encryptedItem = currentUser.encrypt(itemName);
        String encryptedUsername = currentUser.encrypt(loginUsername);
        String encryptedPassword = currentUser.encrypt(loginPassword);

        String compositeKey = encryptedItem + ":" + encryptedUsername;
        
        // Save new login to HashMap
        currentUser.saveLogin(compositeKey, encryptedPassword);
        
        displayOptions();
    }

    /*
    Displays page for searching logins and to modify them (delete/change)
    */
    public static void modifyLogin() {
        if (currentUser.getLocalList().isEmpty()) { // If there are no logins found exit out
            System.out.println("\nNo logins saved yet");
            displayOptions();
            return;
        }

        System.out.print("\nEnter the Login Name you wish to modify: ");
        String itemName = sc.nextLine();

        if (!currentUser.checkLoginExistence(0, itemName)) { // The searched login does not exist
            System.out.println("Could not find \"" + itemName + "\"");
            displayOptions();
            return;
        }

        System.out.print("Enter the Username for this login: ");
        String loginUsername = sc.nextLine();
        
        Map.Entry<String, String[]> loginEntry = currentUser.findLogin(itemName, loginUsername);

        if (loginEntry == null) { // If target key does not exist, exit the user
            System.out.println("Username not found under " + itemName);
            displayOptions();
            return;
        }

        System.out.println("\n(1) Item Name: " + itemName);
        System.out.println("(2) Username: " + loginUsername);
        System.out.println("(3) Password: " + currentUser.decrypt(loginEntry.getValue()[1]));
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

        String currentPassword = currentUser.decrypt(loginEntry.getValue()[1]);

        switch (input) {
            case 1: // Change item name
                System.out.print("New Item Name: ");
                String newItemName = sc.nextLine();

                currentUser.updateLogin(itemName, loginUsername, newItemName, loginUsername, currentPassword);
                break;
            case 2: // Change username
                System.out.print("New Username: ");
                String newUsername = sc.nextLine();

                currentUser.updateLogin(itemName, loginUsername, itemName, newUsername, currentPassword);
                break;
            case 3: // Change password
                System.out.print("New Password: ");
                String newPassword = sc.nextLine();

                currentUser.updateLogin(itemName, loginUsername, itemName, loginUsername, newPassword);
                break;
            case 4: // Delete login
                currentUser.deleteLogin(itemName, loginUsername);
                break;
            default:
                System.out.println("Invalid option");
                displayOptions();
                return;
        }

        displayOptions();
    }

    /*
    Displays all login credentials
    */
    public static void viewLogins() {
        if (currentUser.getLocalList().isEmpty()) { // Exit user if user has no logins
            System.out.println("\nNo logins saved yet");
            displayOptions();
            return;
        }

        System.out.println("\n====YOUR LOGINS====");
        
        // Keep track of the number of logins
        int count = 1;

        // Print out each login
        for (Map.Entry<String, String[]> entry : currentUser.getLocalList().entrySet()) {
            String[] keyParts = entry.getKey().split(":");
            String encryptedItemName = keyParts[0];
            String encryptedUsername = keyParts[1];
            
            String itemName = currentUser.decrypt(encryptedItemName);
            String username = currentUser.decrypt(encryptedUsername);
            String password = currentUser.decrypt(entry.getValue()[1]);
            
            System.out.println((count == 1 ? "" : "\n") + count + ". " + itemName);
            System.out.println("   Username: " + username);
            System.out.println("   Password: " + password);
            
            count++;
        }

        displayOptions();
    }
    
    /*
    Generates a random password based on given length
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
            default:
                return;
        }
    }

    /*
    Loads all users from their credential files onto a HashMap
    */
    public static void loadAllUsers() {
        File usersDir = new File("users/");
        
        if (!usersDir.exists()) {
            usersDir.mkdir();
            return;
        }

        File[] userFolders = usersDir.listFiles(File::isDirectory);

        if (userFolders != null) { // Check existence
            for (File folder : userFolders) { // Loop through each folder in the users directory
                User user = User.loadFromFile(folder.getName());
                
                if (user != null) {
                    allUsers.add(user);
                }
            }
        }
    }

    /*
    Finds and returns a user based on given username
    */
    public static User findUser(String username) {
        for (User user : allUsers) {
            if (user.getUsername().equals(username)) {
                return user;
            }
        }

        return null;
    }
    
    public static void main(String[] args) {
        loadAllUsers();

        System.out.println("====PASSWORD MANAGER====");
        System.out.println("This program manages and saves your online credentials");
        
        while (true) {
            System.out.println("\n1: Login");
            System.out.println("2: Create New Account");
            System.out.println("\nEnter any other key to close the application");

            System.out.print("\nOption: ");
            String input = sc.nextLine();

            if (input.equals("1")) {
                loginPage();
                break;
            } else if (input.equals("2")) {
                accountCreation();
                break;
            } else if (input.equals("3")) {
                break;
            } else {
                break;
            }
        }

        sc.close();
    }
}