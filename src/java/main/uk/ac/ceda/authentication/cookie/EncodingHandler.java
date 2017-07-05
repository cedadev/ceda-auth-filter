package uk.ac.ceda.authentication.cookie;

import com.sun.org.apache.xml.internal.security.exceptions.Base64DecodingException;
import com.sun.org.apache.xml.internal.security.utils.Base64;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.HmacUtils;

/**
 * Class for parsing encoded cookie values.
 * 
 * @author William Tucker
 */
public class EncodingHandler
{
    public static String DEFAULT_DELIMITER = "-";
    
    private String key;
    private String delimiter;
    
    /**
     * Constructor specifying the secret key used for encryption.
     * 
     * @param   key   secure secret key
     */
    public EncodingHandler(String key)
    {
        this.key = key;
        this.delimiter = DEFAULT_DELIMITER;
    }
    
    /**
     * Decodes an encoded cookie value.
     * 
     * @param   message   the text to decode
     * @return  the decoded message
     */
    public String decode(String message)
    {
        String[] content = message.split(this.delimiter);
        String encodedCipherText = content[0];
        String encodedIV = content[1];
        String encodedDigest = content[2];
        
        System.out.println(String.format("Cipher text: %s\nIV: %s\nDigest: %s", encodedCipherText, encodedIV, encodedDigest));
        
        byte[] keyBytes = null, cipherTextBytes = null, ivBytes = null, digestBytes = null;
        try
        {
            keyBytes = Base64.decode(this.key);
            
            cipherTextBytes = Hex.decodeHex(encodedCipherText.toCharArray());
            ivBytes = Hex.decodeHex(encodedIV.toCharArray());
            digestBytes = Hex.decodeHex(encodedDigest.toCharArray());
        }
        catch (DecoderException e)
        {
            e.printStackTrace();
        }
        catch (Base64DecodingException e)
        {
            e.printStackTrace();
        }
        
        String cookieContent = null;
        if (keyBytes != null && cipherTextBytes != null && ivBytes != null && digestBytes != null)
        {
            System.out.println("Verifying signature");
            if (VerifySignature(encodedCipherText.getBytes(), digestBytes, keyBytes))
            {
                System.out.println("Decrypting");
            
                EncryptionHandler encryptionHandler = new EncryptionHandler(keyBytes, ivBytes);
                cookieContent = encryptionHandler.decrypt(cipherTextBytes);
            
                System.out.println(String.format("Cookie content: %s", cookieContent));
            }
            else
            {
                System.out.println("Digests do not match");
            }
        }
        
        return cookieContent;
    }
    
    /**
     * Verifies the signature of encrypted text with a digest.
     * 
     * @param   cipherText  text to verify as a byte array
     * @param   digest      digest to compare as a byte array
     * @param   key         secret key as a byte array
     * @return  whether the signature matched or not
     */
    public static boolean VerifySignature(byte[] cipherText, byte[] digest, byte[] key)
    {
        String originalDigest = new String(digest);
        String calculatedDigest = Sign(key, cipherText);
        
        System.out.println(String.format("Comparing original digest: %s\n   with calculated digest: %s", originalDigest, calculatedDigest));
        
        return calculatedDigest.equals(originalDigest);
    }
    
    /**
     * Calculate a digest for a message from a key.
     * 
     * @param   key     the secret key
     * @param   message text to sign
     * @return  the resulting digest
     */
    public static String Sign(byte[] key, byte[] message)
    {
        byte[] digestBytes = HmacUtils.hmacSha256(key, message);
        
        String digest = new String(digestBytes);
        
        return digest;
    }
}
