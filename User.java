import java.security.*;
import java.util.*;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class User {
    private String username;
    private String passwordHash;
    private byte[] salt;
    private HashMap<String, String[]> localList = new HashMap<>();

    // Create new user data
    public User(String username, String masterPassword) {
        this.username = username;
        this.passwordHash = hashPassword(masterPassword, salt);
        this.salt = generateSalt();
    }

    // Load existing user data
    public User(String username, String passwordHash, byte[] salt) {
        this.username = username;
        this.passwordHash = passwordHash;
        this.salt = salt;
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

    // Check password
    public boolean checkPassword(String enteredPassword) {
        String hashedPassword = hashPassword(enteredPassword, this.salt);
        return hashedPassword.equals(this.passwordHash);
    }

    // Randomly generate a salt
    public static byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] newSalt = new byte[16];
        random.nextBytes(newSalt);

        return newSalt;
    }

    // Getters
    public String getUsername() { return this.getUsername(); }
    public String getPasswordHash() { return this.getPasswordHash(); }
    public byte[] getSalt() { return this.salt; }
    public HashMap<String, String[]> getLocalList() { return this.localList; }

    // Setters
    public void changePassword(String newPassword) {
         this.passwordHash = hashPassword(newPassword, this.salt);
    }
}