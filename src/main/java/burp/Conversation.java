package burp;

/**
 * Conversation Model - Represents a chat message
 * 
 * @author Zahid Eroglu
 */
public class Conversation {
    
    private String sender;  // "user", "assistant", "system"
    private String message;
    private String timestamp;
    
    public Conversation(String sender, String message, String timestamp) {
        this.sender = sender;
        this.message = message;
        this.timestamp = timestamp;
    }

    // Alternative constructor for compatibility (ignores tabId and converts timestamp)
    public Conversation(String tabId, String sender, String message, long timestamp) {
        this.sender = sender;
        this.message = message;
        this.timestamp = String.valueOf(timestamp);
    }
    
    // Getters and Setters
    public String getSender() { return sender; }
    public void setSender(String sender) { this.sender = sender; }

    public String getMessage() { return message; }
    public void setMessage(String message) { this.message = message; }

    public String getTimestamp() { return timestamp; }
    public void setTimestamp(String timestamp) { this.timestamp = timestamp; }

    // Alias method for compatibility
    public String getRole() { return sender; }
}
