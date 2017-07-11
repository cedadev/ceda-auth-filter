package uk.ac.ceda.authentication.filter;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.NoSuchPaddingException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import uk.ac.ceda.authentication.cookie.DecryptionException;
import uk.ac.ceda.authentication.cookie.UserDetailsCookie;
import uk.ac.ceda.authentication.filter.AuthenticateRedirectFilter;

/**
 * Servlet Filter implementation class AuthRedirectFilter
 */
@WebFilter(filterName = "AuthRedirectFilter", urlPatterns = { "/*" },
           description = "Redirects unauthenticated requests to an authentication service.")
public class AuthenticateRedirectFilter implements Filter
{

    private URL authenticateUrl;
    private String redirectQuery;
    
    private String sessionCookieName;
    private String secretKey;
    
    private static final Log LOG = LogFactory.getLog(AuthenticateRedirectFilter.class);
    
    /**
     * @see Filter#doFilter(ServletRequest, ServletResponse, FilterChain)
     */
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException
    {
        if (this.authenticateUrl != null)
        {
            HttpServletRequest httpRequest = (HttpServletRequest) request;
            
            // retrieve session cookie
            String cookieValue = null;
            Cookie[] cookies = httpRequest.getCookies();
            if (cookies != null)
            {
                for (Cookie cookie: cookies)
                {
                    if (cookie.getName().equals(this.sessionCookieName))
                    {
                        cookieValue = cookie.getValue();
                    }
                }
            }
            
            // determine userID from session cookie
            String userID = null;
            if (cookieValue != null)
            {
                try
                {
                    UserDetailsCookie sessionCookie = UserDetailsCookie.parseCookie(
                            this.sessionCookieName, 
                            cookieValue,
                            this.secretKey);
                    userID = sessionCookie.getUserID();
                }
                catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException |
                        InvalidAlgorithmParameterException | DecoderException | DecryptionException e)
                {
                    LOG.error(String.format("Problem parsing cookie value: %s", cookieValue), e);
                }
            }
            
            if (userID == null)
            {
                // userID not found
                // redirect request to authentication service
                StringBuffer requestUrl = httpRequest.getRequestURL();
                
                String query = httpRequest.getQueryString();
                if (query != null)
                {
                    requestUrl.append('?').append(query);
                }
                
                String redirectUrl = getRedirectUrl(requestUrl.toString());
                if (redirectUrl != null)
                {
                    HttpServletResponse httpResponse = (HttpServletResponse) response;
                    httpResponse.sendRedirect(redirectUrl);
                }
            }
        }
        
        // pass the request along the filter chain
        chain.doFilter(request, response);
    }

    /**
     * @see Filter#init(FilterConfig)
     */
    public void init(FilterConfig fConfig) throws ServletException
    {
        try
        {
            this.authenticateUrl = new URL(fConfig.getInitParameter("authenticateUrl"));
        }
        catch (MalformedURLException e)
        {
            LOG.error(String.format("URL, %s, was not a valid format.", this.authenticateUrl), e);
            this.authenticateUrl = null;
        }
        
        this.redirectQuery = fConfig.getInitParameter("redirectQuery");
        
        this.sessionCookieName = fConfig.getInitParameter("sessionCookieName");
        this.secretKey = fConfig.getInitParameter("secretKey");
    }

    public String getRedirectUrl(String returnUrl) throws MalformedURLException, UnsupportedEncodingException
    {
        if (this.authenticateUrl == null)
        {
            return null;
        }
        
        String query = this.authenticateUrl.getQuery();
        
        String queryPrefix = "";
        if (query != null)
        {
            if (query != "" && !query.endsWith("&"))
            {
                queryPrefix = "&";
            }
        }
        else
        {
            queryPrefix = "?";
        }
        
        returnUrl = URLEncoder.encode(returnUrl, "UTF-8");
        
        String redirectUrl = String.format("%s%s%s=%s",
                this.authenticateUrl,
                queryPrefix,
                this.redirectQuery,
                returnUrl
            );
        
        return redirectUrl;
    }

}
