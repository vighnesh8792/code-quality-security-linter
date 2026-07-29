import java.util.*; // STY007: Wildcard import detected
import java.io.*;
import java.security.MessageDigest;

// STY003: Class name may violate PascalCase (should be TestClass)
public class testClass {

    // QUA012: Public mutable field & SEC001: Hardcoded password
    public String password = "SuperSecretPassword123!"; 
    
    // SEC002: Hardcoded API key
    public String apiKey = "AB34567890-XYZ-TOKEN";

    // QUA008: Generic exception declared
    public void processUserData(String userName) throws Exception {
        
        // QUA002: System.out.println used
        System.out.println("Starting data process..."); 
        
        // STY004: Magic number detected
        int timeout = 5000; 
        
        // SEC003: SQL Injection risk & SEC004: Statement used
        String query = "SELECT * FROM users WHERE name = " + userName;
        
        // STY002: String comparison using ==
        if (userName == "admin") {
            // QUA005: Empty if block found
        }
        
        try {
            // SEC007: Weak hash algorithm
            MessageDigest md = MessageDigest.getInstance("MD5");
            
            // SEC008: Insecure HTTP
            String url = "http://my-insecure-api.com/data"; 
            
            // SEC005: Command execution detected
            Runtime.getRuntime().exec("ping " + url); 
            
            // QUA007: Thread.sleep used directly
            Thread.sleep(timeout);
            
            // PER004: Nested loops suspected
            for (int i = 0; i < 10; i++) {
                for (int j = 0; j < 5; j++) {
                    // PER001: Repeated string concatenation
                    String log = "Loop " + i + " and " + j; 
                }
            }
            
            // STY006: Commented-out code detected
            // System.out.println("Debugging loops..."); 
            
            // SEC011: Path traversal pattern
            File secretFile = new File("../../../etc/passwd"); 
            
        } catch (Exception e) { 
            // QUA001: Empty catch block & QUA009: Generic catch(Exception)
        }
        
        // QUA004: TODO comment found
        // TODO: We need to fix this method later, it is very bad!
        
        // STY001: Line exceeds 120 characters
        String veryLongString = "This is a ridiculously long string that is definitely going to cross the one hundred and twenty character limit and trigger the style warning for sure.";
    }

    public Object getResult() {
        // QUA010: return null detected
        return null;
    }
}