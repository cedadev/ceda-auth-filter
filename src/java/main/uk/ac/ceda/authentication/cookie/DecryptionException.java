package uk.ac.ceda.authentication.cookie;

public class DecryptionException extends Exception
{

    /**
     * Exception thrown when a problem occurs during decryption.
     */
    private static final long serialVersionUID = 1L;

    public DecryptionException(String message, Throwable cause)
    {
        super(message, cause);
    }

    public DecryptionException(String message)
    {
        super(message);
    }

}
