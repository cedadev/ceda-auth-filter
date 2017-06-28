package uk.ac.ceda.authentication.cookie;

import java.sql.Timestamp;
import java.util.Arrays;
import java.util.regex.Pattern;

public class UserDetailsCookie extends SecureCookie
{
    public static String BODY_SEPARATOR = "!";
    public static String TIMESTAMP_FORMAT = "%08d";
    
    private Timestamp timestamp;
    private String userID;
    private String tokens;
    private String[] userData;
    
    public UserDetailsCookie(String name, String key, Timestamp timestamp, String userID, String tokens, String[] userData)
    {
        super(name, key);
        
        this.timestamp = timestamp;
        this.userID = userID;
        this.tokens = tokens;
        this.userData = userData;
    }
    
    public static UserDetailsCookie parseCookie(String name, String encodedValue, String key)
    {
        SecureCookie cookie = SecureCookie.parseCookie(name, encodedValue, key);
        String cookieContent = cookie.getValue();
        
        Timestamp timestamp = null;
        String userID = null;
        String tokens = null;
        String[] userData = null;
        if (cookieContent != null)
        {
            try
            {
                timestamp = new Timestamp(Long.parseLong(cookieContent.substring(0, 8), 16));
                System.out.println(String.format("timestamp: %s", timestamp.toString()));
            }
            catch (NumberFormatException e)
            {
                e.printStackTrace();
            }
        
            String cookieBody = cookieContent.substring(8);
            if (!cookieBody.contains(BODY_SEPARATOR))
            {
                System.out.println("Bad cookie format");
            }
        
            String[] bodyParts = cookieBody.split(Pattern.quote(BODY_SEPARATOR), 2);
            userID = bodyParts[0];
            System.out.println(String.format("userID: %s", userID));
            if (bodyParts.length > 1)
            {
                userData = bodyParts[1].split(Pattern.quote(BODY_SEPARATOR));
                if (userData.length > 1)
                {
                    tokens = userData[0];
                    userData = Arrays.copyOfRange(userData, 1, userData.length);
                }
            }
            System.out.println(String.format("tokens: %s", tokens));
            System.out.println("userData:");
            if (userData != null)
            {
                for (String dataValue : userData)
                {
                    System.out.println(dataValue);
                }
            }
        }
    
        UserDetailsCookie details = new UserDetailsCookie(name, key, timestamp, userID, tokens, userData);
        
        return details;
    }
    
    @Override
    public String getValue()
    {
        return super.getValue();
    }
    
    public Timestamp getTimestamp()
    {
        return timestamp;
    }
    
    public String getUserID()
    {
        return userID;
    }
    
    public String getTokens()
    {
        return tokens;
    }
    
    public String[] getUserData()
    {
        return userData;
    }
}
