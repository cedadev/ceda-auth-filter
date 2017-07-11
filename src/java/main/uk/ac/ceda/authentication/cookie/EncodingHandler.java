package uk.ac.ceda.authentication.cookie;

import org.apache.commons.codec.binary.Base64;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.HmacUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

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
    
    private static final Log LOG = LogFactory.getLog(EncodingHandler.class);
    
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
     * @throws DecoderException 
     * @throws NoSuchPaddingException 
     * @throws NoSuchAlgorithmException 
     * @throws DecryptionException 
     * @throws InvalidAlgorithmParameterException 
     * @throws InvalidKeyException 
     */
    public String decode(String message)
            throws DecoderException, NoSuchAlgorithmException, NoSuchPaddingException,
                    InvalidKeyException, InvalidAlgorithmParameterException, DecryptionException
    {
        String[] content = message.split(this.delimiter);
        String encodedCipherText = content[0];
        String encodedIV = content[1];
        String encodedDigest = content[2];
        
        if (LOG.isDebugEnabled())
            LOG.debug(String.format("Cipher text: %s\nIV: %s\nDigest: %s",
                    encodedCipherText, encodedIV, encodedDigest));
        
        byte[] keyBytes = Base64.decodeBase64(this.key);
        
        byte[] cipherTextBytes = Hex.decodeHex(encodedCipherText.toCharArray());
        byte[] ivBytes = Hex.decodeHex(encodedIV.toCharArray());
        byte[] digestBytes = Hex.decodeHex(encodedDigest.toCharArray());
        
        String cookieContent = null;
        if (keyBytes != null && cipherTextBytes != null && ivBytes != null && digestBytes != null)
        {
            if (LOG.isDebugEnabled())
                LOG.debug("Verifying signature");
            if (VerifySignature(encodedCipherText.getBytes(), digestBytes, keyBytes))
            {
                if (LOG.isDebugEnabled())
                    LOG.debug("Decrypting");
                
                EncryptionHandler encryptionHandler = new EncryptionHandler(keyBytes, ivBytes);
                
                cookieContent = encryptionHandler.decrypt(cipherTextBytes);
            
                if (LOG.isDebugEnabled())
                    LOG.debug(String.format("Cookie content: %s", cookieContent));
            }
            else
            {
                if (LOG.isDebugEnabled())
                    LOG.debug("Digests do not match");
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
        
        if (LOG.isDebugEnabled())
            LOG.debug(String.format("Comparing original digest: %s\n   with calculated digest: %s",
                    originalDigest, calculatedDigest));
        
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
