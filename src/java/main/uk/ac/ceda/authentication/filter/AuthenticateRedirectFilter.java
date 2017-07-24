package uk.ac.ceda.authentication.filter;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
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
 * 
 * @author William Tucker
 */
@WebFilter(filterName = "AuthRedirectFilter", urlPatterns = { "/*" },
           description = "Redirects unauthenticated requests to an authentication service.")
public class AuthenticateRedirectFilter implements Filter
{

    private String requestAttribute;
    
    private URL authenticateUrl;
    private String redirectQuery;
    
    private String sessionCookieName;
    private String secretKey;
    
    private static final Log LOG = LogFactory.getLog(AuthenticateRedirectFilter.class);
    
    /**
     * @see Filter#destroy()
     */
    public void destroy()
    {
        
    }
    
    /**
     * @see Filter#doFilter(ServletRequest, ServletResponse, FilterChain)
     */
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException
    {
        if (this.authenticateUrl == null)
        {
            LOG.warn("Authenticate URL not specified in config; skipping filter.");
        }
        else
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
                        
                        if (LOG.isDebugEnabled())
                            LOG.debug(String.format("Found session cookie: %s", cookieValue));
                    }
                }
            }
            
            if (cookieValue == null)
            {
                // session cookie not found
                // redirect request to authentication service
                StringBuffer requestUrl = httpRequest.getRequestURL();
                
                String query = httpRequest.getQueryString();
                if (query != null)
                {
                    requestUrl.append('?').append(query);
                }
                
                try
                {
                    String redirectUrl = getRedirectUrl(requestUrl.toString());
                    
                    // send the redirect
                    HttpServletResponse httpResponse = (HttpServletResponse) response;
                    httpResponse.sendRedirect(redirectUrl);
                    
                    if (LOG.isDebugEnabled())
                        LOG.debug(String.format(
                                "Session cookie not found; redirecting to: %s", redirectUrl));
                }
                catch (MalformedURLException | UnsupportedEncodingException e)
                {
                    LOG.error("Failed to construct redirect reponse.", e);
                }
            }
            else
            {
                // determine userID from session cookie
                String userID = null;
                try
                {
                    // parse a user ID from the cookie value
                    UserDetailsCookie sessionCookie = UserDetailsCookie.parseCookie(
                            this.sessionCookieName, 
                            cookieValue,
                            this.secretKey);
                    userID = sessionCookie.getUserID();
                    
                    if (LOG.isDebugEnabled())
                        LOG.debug(String.format("Found user ID: %s", userID));
                }
                catch (NoSuchAlgorithmException | NoSuchPaddingException e)
                {
                    LOG.error("Failed to load decoding/decryption handlers.", e);
                }
                catch (DecoderException | DecryptionException e)
                {
                    if (LOG.isDebugEnabled())
                        LOG.debug(String.format("Problem parsing cookie value: %s", cookieValue));
                }
                
                if (userID == null)
                {
                    // userID not found in cookie
                    // send 401 response
                    HttpServletResponse httpResponse = (HttpServletResponse) response;
                    httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, "User not found.");
                }
                else
                {
                    // set request attribute indicating authentication success
                    httpRequest.setAttribute(this.requestAttribute, userID);
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
        String authenticateUrl = fConfig.getInitParameter("authenticateUrl");
        if (authenticateUrl != null)
        {
            try
            {
                this.authenticateUrl = new URL(authenticateUrl);
            }
            catch (MalformedURLException e)
            {
                LOG.error(String.format("%s is not a valid URL.", authenticateUrl), e);
                this.authenticateUrl = null;
            }
        }
        
        this.redirectQuery = fConfig.getInitParameter("redirectQuery");
        
        this.sessionCookieName = fConfig.getInitParameter("sessionCookieName");
        this.secretKey = fConfig.getInitParameter("secretKey");
        
        this.requestAttribute = fConfig.getInitParameter("requestAttribute");
    }
    
    /**
     * Construct a redirection URL based on config settings.
     * 
     * @param returnUrl URL to return to after authentication
     * @return  redirect URL
     * @throws MalformedURLException
     * @throws UnsupportedEncodingException
     */
    public String getRedirectUrl(String returnUrl) throws MalformedURLException, UnsupportedEncodingException
    {
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
        
        URL redirectUrl = new URL(String.format("%s%s%s=%s",
                this.authenticateUrl,
                queryPrefix,
                this.redirectQuery,
                returnUrl
            ));
        
        return redirectUrl.toString();
    }

}
