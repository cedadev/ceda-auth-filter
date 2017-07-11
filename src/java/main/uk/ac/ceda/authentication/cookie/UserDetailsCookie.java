package uk.ac.ceda.authentication.cookie;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.sql.Timestamp;
import java.util.Arrays;
import java.util.regex.Pattern;

import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class UserDetailsCookie extends SecureCookie
{
    public static String BODY_SEPARATOR = "!";
    public static String TIMESTAMP_FORMAT = "%08d";
    
    private Timestamp timestamp;
    private String userID;
    private String[] tokens;
    private String userData;

    private static final Log LOG = LogFactory.getLog(UserDetailsCookie.class);
    
    public UserDetailsCookie(String name, String key, Timestamp timestamp, String userID, String[] tokens, String userData)
    {
        super(name, key);
        
        this.timestamp = timestamp;
        this.userID = userID;
        this.tokens = tokens;
        this.userData = userData;
    }
    
    public static UserDetailsCookie parseCookie(String name, String encodedValue, String key)
            throws NoSuchAlgorithmException, NoSuchPaddingException, DecoderException,
                InvalidKeyException, InvalidAlgorithmParameterException, DecryptionException
    {
        SecureCookie cookie = SecureCookie.parseCookie(name, encodedValue, key);
        String cookieContent = cookie.getValue();
        
        Timestamp timestamp = null;
        String userID = null;
        String[] tokens = null;
        String userData = null;
        if (cookieContent != null)
        {
            try
            {
                timestamp = new Timestamp(Long.parseLong(cookieContent.substring(0, 8), 16));
                if (LOG.isDebugEnabled())
                    LOG.debug(String.format("timestamp: %s", timestamp.toString()));
            }
            catch (NumberFormatException e)
            {
                e.printStackTrace();
            }
        
            String cookieBody = cookieContent.substring(8);
            if (!cookieBody.contains(BODY_SEPARATOR))
            {
                if (LOG.isDebugEnabled())
                    LOG.debug("Bad cookie format");
            }
        
            String[] parts = cookieBody.split(Pattern.quote(BODY_SEPARATOR), 2);
            userID = parts[0];
            if (LOG.isDebugEnabled())
                LOG.debug(String.format("userID: %s", userID));
            if (parts.length > 1)
            {
                parts = parts[1].split(Pattern.quote(BODY_SEPARATOR));
                if (parts.length == 2)
                {
                    // tokens are comma separated
                    tokens = parts[0].split(Pattern.quote(","));
                    userData = parts[1];
                }
                else if (parts.length == 1)
                {
                    userData = parts[0];
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
    
    public String[] getTokens()
    {
        return tokens;
    }
    
    public String getUserData()
    {
        return userData;
    }
}
