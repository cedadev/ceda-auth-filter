package uk.ac.ceda.authentication.cookie;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.DecoderException;

public class SecureCookie
{
    private String name;
    private String value;
    
    public SecureCookie(String name, String value)
    {
        this.name = name;
        this.value = value;
    }
    
    public SecureCookie(String name)
    {
        this(name, null);
    }
    
    public static SecureCookie parseCookie(String name, String encodedValue, String key)
            throws NoSuchAlgorithmException, NoSuchPaddingException, DecoderException,
                InvalidKeyException, InvalidAlgorithmParameterException, DecryptionException
    {
        EncodingHandler encodingHandler = new EncodingHandler(key);
        String decodedValue = encodingHandler.decode(encodedValue);
        
        SecureCookie secureCookie = new SecureCookie(name, decodedValue);
        
        return secureCookie;
    }
    
    public String getName()
    {
        return name;
    }
    
    public String getValue()
    {
        return value;
    }
}
