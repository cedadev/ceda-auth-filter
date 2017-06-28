package uk.ac.ceda.authentication.cookie;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.regex.Pattern;

public class EncryptionHandler
{
    public static char DEFAULT_PADDING_CHAR = ' ';
    public static String DEFAULT_SECRET_KEY_SPEC = "AES";
    public static String DEFAULT_CIPHER = "AES/CBC/NoPadding";
    
    private SecretKey key;
    private Cipher cipher;
    private IvParameterSpec iv;
    private char paddingChar;
    
    public EncryptionHandler(byte[] keyBytes, byte[] ivBytes)
    {
        this.key = new SecretKeySpec(keyBytes, 0, keyBytes.length,
                DEFAULT_SECRET_KEY_SPEC);
        this.iv = new IvParameterSpec(ivBytes);
        this.paddingChar = DEFAULT_PADDING_CHAR;
        
        try
        {
            this.cipher = Cipher.getInstance(DEFAULT_CIPHER);
        }
        catch (NoSuchAlgorithmException e)
        {
            e.printStackTrace();
        }
        catch (NoSuchPaddingException e)
        {
            e.printStackTrace();
        }
    }
    
    public String decrypt(byte[] cipherTextBytes)
    {
        String textValue = null;
        try
        {
            this.cipher.init(Cipher.DECRYPT_MODE, this.key, this.iv);
            
            byte[] plainTextBytes = this.cipher.doFinal(cipherTextBytes);
            
            textValue = new String(plainTextBytes, "UTF-8");
            String regex = String.format("%s+$", Pattern.quote(String.valueOf(this.paddingChar)));
            textValue = textValue.replaceAll(regex, "");
        }
        catch (InvalidKeyException e)
        {
            e.printStackTrace();
        }
        catch (BadPaddingException e)
        {
            e.printStackTrace();
        }
        catch (IllegalBlockSizeException e)
        {
            e.printStackTrace();
        }
        catch (InvalidAlgorithmParameterException e)
        {
            e.printStackTrace();
        }
        catch (UnsupportedEncodingException e)
        {
            e.printStackTrace();
        }
        
        return textValue;
    }
}
