package uk.ac.ceda.authentication.cookie;

import java.security.NoSuchAlgorithmException;

import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.DecoderException;

/**
 * Class encapsulating an encrypted cookie.
 * 
 * @author William Tucker
 */
public class SecureCookie
{
    private String name;
    private String value;
    
    /**
     * Constructor taking a cookie name and value.
     * 
     * @param name  cookie name
     * @param value cookie value
     */
    public SecureCookie(String name, String value)
    {
        this.name = name;
        this.value = value;
    }
    
    /**
     * Parses an encrypted cookie value.
     * 
     * @param name          cookie name
     * @param encodedValue  encoded value
     * @param key           secret key for decryption
     * @return  parsed value
     * @throws NoSuchPaddingException 
     * @throws NoSuchAlgorithmException 
     * @throws DecryptionException 
     * @throws DecoderException 
     */
    public static SecureCookie parseCookie(String name, String encodedValue, String key) throws
            NoSuchAlgorithmException, NoSuchPaddingException, DecoderException, DecryptionException
    {
        EncodingHandler encodingHandler = new EncodingHandler(key);
        String decodedValue = encodingHandler.decode(encodedValue);
        
        SecureCookie secureCookie = new SecureCookie(name, decodedValue);
        
        return secureCookie;
    }
    
    /**
     * Gets the name of the cookie.
     * 
     * @return  the cookie name
     */
    public String getName()
    {
        return name;
    }
    
    /**
     * Gets the plain text value of the cookie.
     * 
     * @return  the cookie value
     */
    public String getValue()
    {
        return value;
    }
}
