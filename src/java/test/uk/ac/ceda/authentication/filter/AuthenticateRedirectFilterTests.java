package uk.ac.ceda.authentication.filter;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.stream.Stream;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class AuthenticateRedirectFilterTests
{

    private static final String AUTHENTICATE_URL_PARAM = "authenticateUrl";
    private static final String AUTHENTICATE_URL =
            "https://auth-test.ceda.ac.uk/account/signin/";
    
    private static final String REDIRECT_QUERY_PARAM = "redirectQuery";
    private static final String REDIRECT_QUERY = "r";
    
    private static final String SECRET_KEY_PARAM = "secretKey";
    private static final String COOKIE_NAME_PARAM = "sessionCookieName";
    private static final String COOKIE_NAME = "session-cookie";
    
    @Mock
    private HttpServletRequest mockRequest;
    
    @Mock
    private HttpServletResponse mockResponse;
    
    @Mock
    private FilterChain mockFilterChain;
    
    @Mock
    private FilterConfig mockFilterConfig;
    
    @Captor
    private ArgumentCaptor<String> stringCaptor;
    
    private AuthenticateRedirectFilter filter;
    private String expectedPrefix;
    
    @Before
    public void setUp() throws Exception
    {
        expectedPrefix = String.format("%s?%s=", AUTHENTICATE_URL, REDIRECT_QUERY);
        
        when(mockFilterConfig.getInitParameter(AUTHENTICATE_URL_PARAM)).thenReturn(
                AUTHENTICATE_URL);
        when(mockFilterConfig.getInitParameter(REDIRECT_QUERY_PARAM)).thenReturn(
                REDIRECT_QUERY);
        
        filter = new AuthenticateRedirectFilter();
        filter.init(mockFilterConfig);
    }
    
    @After
    public void tearDown() throws Exception
    {
        filter.destroy();
    }
    
    @Test
    public void testDoFilter() throws IOException, ServletException
    {
        // mock the getRequestURI() response
        StringBuffer requestUrl = new StringBuffer("http://localhost:8080/");
        when(mockRequest.getRequestURL()).thenReturn(requestUrl);
        
        filter.doFilter(mockRequest, mockResponse, mockFilterChain);
        
        // capture the redirect URL
        verify(mockResponse).sendRedirect(stringCaptor.capture());
        
        String result = stringCaptor.getValue();
        assertEquals(result, expectedPrefix + "http%3A%2F%2Flocalhost%3A8080%2F");
    }
    
    @Test
    public void testDoFilter_authenticated() throws URISyntaxException, IOException, ServletException
    {
        ClassLoader loader = Test.class.getClassLoader();
        Path cookieInfoPath = Paths.get(loader.getResource(
                "uk/ac/ceda/authentication/cookie/sample_cookies/user-details-cookie-info").toURI());
        
        Stream<String> stream = Files.lines(cookieInfoPath);
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
        stream.close();
        
        String secretKey = valueMap.get("encoded_secret_key");
        String cookieValue = valueMap.get("cookie_value");
        
        when(mockFilterConfig.getInitParameter(SECRET_KEY_PARAM)).thenReturn(
                secretKey);
        when(mockFilterConfig.getInitParameter(COOKIE_NAME_PARAM)).thenReturn(
                COOKIE_NAME);
        
        filter = new AuthenticateRedirectFilter();
        filter.init(mockFilterConfig);
        
        Cookie[] cookies = new Cookie[1];
        cookies[0] = new Cookie(COOKIE_NAME, cookieValue);
        
        // insert the cookie into the request
        when(mockRequest.getCookies()).thenReturn(cookies);
        
        // mock the getRequestURI() response
        StringBuffer requestUrl = new StringBuffer("http://localhost:8080/");
        when(mockRequest.getRequestURL()).thenReturn(requestUrl);
        
        filter.doFilter(mockRequest, mockResponse, mockFilterChain);
    }

    @Test
    public void testDoFilter_badCookie() throws URISyntaxException, IOException, ServletException
    {
        String secretKey = "";
        String cookieValue = "";
        
        when(mockFilterConfig.getInitParameter(SECRET_KEY_PARAM)).thenReturn(
                secretKey);
        when(mockFilterConfig.getInitParameter(COOKIE_NAME_PARAM)).thenReturn(
                COOKIE_NAME);
        
        filter = new AuthenticateRedirectFilter();
        filter.init(mockFilterConfig);
        
        Cookie[] cookies = new Cookie[1];
        cookies[0] = new Cookie(COOKIE_NAME, cookieValue);
        
        // insert the cookie into the request
        when(mockRequest.getCookies()).thenReturn(cookies);
        
        // mock the getRequestURI() response
        StringBuffer requestUrl = new StringBuffer("http://localhost:8080/");
        when(mockRequest.getRequestURL()).thenReturn(requestUrl);
        
        filter.doFilter(mockRequest, mockResponse, mockFilterChain);
    }
    
    @Test
    public void testGetRedirectUrl_simpleAuthUrl() throws ServletException, MalformedURLException,
            UnsupportedEncodingException
    {
        String url, expectedUrl, redirectUrl;
        
        // Without query string
        url = "http://localhost:8080/";
        expectedUrl = expectedPrefix + "http%3A%2F%2Flocalhost%3A8080%2F";
        redirectUrl = filter.getRedirectUrl(url);

        assertEquals(redirectUrl, expectedUrl);

        // With query string
        url = "http://localhost:8080/?key=value";
        expectedUrl = expectedPrefix + "http%3A%2F%2Flocalhost%3A8080%2F%3Fkey%3Dvalue";
        redirectUrl = filter.getRedirectUrl(url);

        assertEquals(redirectUrl, expectedUrl);
    }

    @Test
    public void testGetRedirectUrl_complexAuthUrl() throws ServletException, MalformedURLException,
            UnsupportedEncodingException
    {
        String authenticateUrl = AUTHENTICATE_URL + "?key=value";
        String expectedPrefix = String.format("%s&%s=", authenticateUrl, REDIRECT_QUERY);
        
        when(mockFilterConfig.getInitParameter(AUTHENTICATE_URL_PARAM)).thenReturn(
                authenticateUrl);
        
        filter = new AuthenticateRedirectFilter();
        filter.init(mockFilterConfig);
        
        String url, expectedUrl, redirectUrl;
        
        // Without query string
        url = "http://localhost:8080/";
        expectedUrl = expectedPrefix + "http%3A%2F%2Flocalhost%3A8080%2F";
        redirectUrl = filter.getRedirectUrl(url);

        assertEquals(redirectUrl, expectedUrl);

        // With query string
        url = "http://localhost:8080/?key=value";
        expectedUrl = expectedPrefix + "http%3A%2F%2Flocalhost%3A8080%2F%3Fkey%3Dvalue";
        redirectUrl = filter.getRedirectUrl(url);

        assertEquals(redirectUrl, expectedUrl);
    }

}
