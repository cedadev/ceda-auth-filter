package uk.ac.ceda.authentication.cookie;

import static org.junit.Assert.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.stream.Stream;

import javax.crypto.NoSuchPaddingException;

import org.junit.Before;
import org.junit.Test;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;

public class UserDetailsCookieTests
{

    String secretKey;
    String userID;
    String[] tokens;
    String userData;
    String cookieValue;
    
    @Before
    public void setUp() throws Exception
    {
        ClassLoader loader = Test.class.getClassLoader();
        Path cookieInfoPath = Paths.get(loader.getResource("uk/ac/ceda/authentication/cookie/sample_cookies/user-details-cookie-info").toURI());
        
        secretKey = null;
        userID = null;
        tokens = null;
        userData = null;
        try (Stream<String> stream = Files.lines(cookieInfoPath))
        {
            HashMap<String, String> valueMap = new HashMap<String, String>();
            stream.forEach(line -> {
                String[] parts = line.split(" ", 2);
                if (parts.length > 1)
                {
                    String key = parts[0].replaceAll(":", "");
                    String value = parts[1];
                    
                    valueMap.put(key, value);
                }
            });
            
            secretKey = valueMap.get("secret_key");
            if (secretKey != null)
                secretKey = Base64.encodeBase64String(secretKey.getBytes());
            cookieValue = valueMap.get("cookie_value");
            
            userID = valueMap.get("userid");
            tokens = valueMap.get("tokens").split(",");
            userData = valueMap.get("user_data");
        }
        catch (IOException e)
        {
            e.printStackTrace();
        }
    }

    @Test
    public void testParseCookie()
            throws NoSuchAlgorithmException, NoSuchPaddingException, DecoderException,
                InvalidKeyException, InvalidAlgorithmParameterException, DecryptionException
    {
        UserDetailsCookie cookie = UserDetailsCookie.parseCookie("", this.cookieValue, this.secretKey);
        
        assertEquals(cookie.getUserID(), this.userID);
        assertEquals(cookie.getTokens(), this.tokens);
        assertEquals(cookie.getUserData(), this.userData);
    }

}
