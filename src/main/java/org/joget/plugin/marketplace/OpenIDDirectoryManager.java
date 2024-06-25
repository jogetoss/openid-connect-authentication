package org.joget.plugin.marketplace;

import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.nimbusds.openid.connect.sdk.claims.ClaimsSet;
import org.joget.apps.app.service.AppUtil;
import org.joget.apps.workflow.security.WorkflowUserDetails;
import org.joget.commons.util.LogUtil;
import org.joget.commons.util.ResourceBundleUtil;
import org.joget.directory.dao.RoleDao;
import org.joget.directory.dao.UserDao;
import org.joget.directory.ext.DirectoryManagerAuthenticatorImpl;
import org.joget.directory.model.Role;
import org.joget.directory.model.User;
import org.joget.directory.model.service.DirectoryManager;
import org.joget.directory.model.service.DirectoryManagerAuthenticator;
import org.joget.directory.model.service.DirectoryManagerProxyImpl;
import org.joget.directory.model.service.UserSecurityFactory;
import org.joget.plugin.base.PluginManager;
import org.joget.plugin.directory.SecureDirectoryManager;
import org.joget.plugin.directory.SecureDirectoryManagerImpl;
import org.joget.workflow.model.dao.WorkflowHelper;
import org.joget.workflow.util.WorkflowUtil;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.net.URI;
import java.net.URLDecoder;
import net.sf.ehcache.Cache;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

public class OpenIDDirectoryManager extends SecureDirectoryManager {

    public SecureDirectoryManagerImpl dirManager;

    @Override
    public String getName() {
        return "OpenID Connect Directory Manager";
    }

    @Override
    public String getDescription() {
        return "Directory Manager with support for OpenID Connect";
    }

    @Override
    public String getVersion() {
        return "7.0.5";
    }

    @Override
    public DirectoryManager getDirectoryManagerImpl(Map properties) {
        if (dirManager == null) {
            dirManager = new ExtSecureDirectoryManagerImpl(properties);
        } else {
            dirManager.setProperties(properties);
        }

        return dirManager;
    }

    @Override
    public String getPropertyOptions() {
        UserSecurityFactory f = (UserSecurityFactory) new SecureDirectoryManagerImpl(null);
        String usJson = f.getUserSecurity().getPropertyOptions();
        usJson = usJson.replaceAll("\\n", "\\\\n");

        String addOnJson = "";
        if (SecureDirectoryManagerImpl.NUM_OF_DM > 1) {
            for (int i = 2; i <= SecureDirectoryManagerImpl.NUM_OF_DM; i++) {
                addOnJson += ",{\nname : 'dm" + i + "',\n label : '@@app.edm.label.addon@@',\n type : 'elementselect',\n";
                addOnJson += "options_ajax : '[CONTEXT_PATH]/web/json/plugin/org.joget.plugin.directory.SecureDirectoryManager/service',\n";
                addOnJson += "url : '[CONTEXT_PATH]/web/property/json/getPropertyOptions'\n}";
            }
        }

        HttpServletRequest request = WorkflowUtil.getHttpServletRequest();
        String callbackUrl = request.getScheme() + "://" + request.getServerName();
        if (request.getServerPort() != 80 && request.getServerPort() != 443) {
            callbackUrl += ":" + request.getServerPort();
        }
        callbackUrl += request.getContextPath() + "/web/json/plugin/org.joget.plugin.marketplace.OpenIDDirectoryManager/service";
        String entityId = callbackUrl;

        String json = AppUtil.readPluginResource(getClass().getName(), "/properties/app/OpenIDDirectoryManager.json", new String[]{callbackUrl, usJson, addOnJson}, true, "messages/open-id-authentication");
        return json;
    }

    @Override
    public String getLabel() {
        return "OpenID Connect Directory Manager";
    }

    @Override
    public String getClassName() {
        return getClass().getName();
    }

    public static String getCallbackURL() {
        HttpServletRequest request = WorkflowUtil.getHttpServletRequest();
        String callbackUrl = request.getScheme() + "://" + request.getServerName();
        if (request.getServerPort() != 80 && request.getServerPort() != 443) {
            callbackUrl += ":" + request.getServerPort();
        }
        callbackUrl += request.getContextPath() + "/web/json/plugin/org.joget.plugin.marketplace.OpenIDDirectoryManager/service";
        return callbackUrl;
    }

    @Override
    public void webService(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String url = request.getContextPath() + "/web/login?login_error=1";
        String action = request.getParameter("action");
        try {
            if ("dmOptions".equals(action)) {
                super.webService(request, response);
            } else if (request.getParameter("login") != null) {
                Nonce nonce = new Nonce();
                State state = new State();

                net.sf.ehcache.Element element = new net.sf.ehcache.Element(state.toString(), nonce.toString());
                element.setEternal(false);
                element.setTimeToLive(60);

                Cache cache = (Cache) AppUtil.getApplicationContext().getBean("nonceCache");
                cache.put(element);

                // Generate the auth endpoint URI to request the auth code
                URI authorizationEndpoint = getAuthorizationEndpointUri(nonce, state);
                // Create the user agent and make the call to the auth endpoint
                response.sendRedirect(authorizationEndpoint.toString());

            } else if (request.getParameter("code") != null) {
                //receive response from identity provider
                AuthenticationResponse authResp = null;
                AuthorizationCode authCode = null;
                authResp = AuthenticationResponseParser.parse(new URI(request.getRequestURI() + "?" + request.getQueryString()));
                Nonce nonce = null;
                        
                State state = new State(request.getParameter("state"));
                Cache cache = (Cache) AppUtil.getApplicationContext().getBean("nonceCache");
                net.sf.ehcache.Element element = cache.get(state.toString());
                if (element != null) {
                    nonce = new Nonce(element.getObjectValue().toString());
                }

                if (authResp instanceof AuthenticationErrorResponse) {
                    ErrorObject error = ((AuthenticationErrorResponse) authResp).getErrorObject();
                    LogUtil.error(OpenIDDirectoryManager.class.getName(), null, "Error During Authentication Response: " + error.toString());
                    request.getSession().setAttribute("SPRING_SECURITY_LAST_EXCEPTION", "Error in Redirecting To External Login Page");
                    response.sendRedirect(url);
                }

                AuthenticationSuccessResponse successResponse = (AuthenticationSuccessResponse) authResp;
                if (successResponse != null) {
                    if (!state.equals(successResponse.getState())) {
                        LogUtil.error(OpenIDDirectoryManager.class.getName(), null, "Unexpected authentication response");
                        request.getSession().setAttribute("SPRING_SECURITY_LAST_EXCEPTION", "Error in Redirecting To External Login Page");
                        response.sendRedirect(url);
                    } else {
                        authCode = successResponse.getAuthorizationCode();
                    }
                }
                if (authCode != null) {
                    String code = URLDecoder.decode(authCode.getValue(), "UTF-8");
                    Object[] accessTokenArray = getTokenForCode(code, nonce);
                    AccessToken accessToken = (AccessToken) accessTokenArray[0];
                    ClaimsSet idTokenClaims = (ClaimsSet) accessTokenArray[1];
                    UserInfo userInfo = getUserInfo(accessToken);
                    userInfo.putAll(idTokenClaims);
                    doLogin(userInfo, request, response);
                }
            } else {
                response.sendError(HttpServletResponse.SC_NO_CONTENT);
            }
        } catch (IOException | URISyntaxException | ParseException ex) {
            LogUtil.error(OpenIDDirectoryManager.class.getName(), ex, "Error in Redirecting To External Login Page");
            request.getSession().setAttribute("SPRING_SECURITY_LAST_EXCEPTION", "Error in Redirecting To External Login Page");
            response.sendRedirect(url);
        }
    }

    public OIDCProviderMetadata IssuerDiscovery() throws IOException, URISyntaxException {
        DirectoryManagerProxyImpl dm = (DirectoryManagerProxyImpl) AppUtil.getApplicationContext().getBean("directoryManager");
        SecureDirectoryManagerImpl dmImpl = (SecureDirectoryManagerImpl) dm.getDirectoryManagerImpl();

        //URI issuerURI = new URI(dmImpl.getPropertyString("issuerUrl"));
        //URL providerConfigurationURL = issuerURI.resolve("/.well-known/openid-configuration").toURL();

        URI issuerURI = new URI(dmImpl.getPropertyString("issuerUrl") + "/.well-known/openid-configuration");
        URL providerConfigurationURL = issuerURI.toURL();
        InputStream stream = providerConfigurationURL.openStream();
        //OIDCClientInformation clientInformation = null;
        // Read all data from URL
        String providerInfo = null;
        try (java.util.Scanner s = new java.util.Scanner(stream)) {
            providerInfo = s.useDelimiter("\\A").hasNext() ? s.next() : "";
        }
        OIDCProviderMetadata providerMetadata = null;
        try {
            providerMetadata = OIDCProviderMetadata.parse(providerInfo);
        } catch (ParseException ex) {
            LogUtil.error(OpenIDDirectoryManager.class.getName(), ex, "Error on Issuer Discovery");
            return null;
        }
        return providerMetadata;
    }

    /**
     * Build the authorization request URL
     *
     * @param nonce
     * @param state
     * @return
     * @throws URISyntaxException
     * @throws java.io.IOException
     */
    public URI getAuthorizationEndpointUri(Nonce nonce, State state) throws URISyntaxException, IOException {
        DirectoryManagerProxyImpl dm = (DirectoryManagerProxyImpl) AppUtil.getApplicationContext().getBean("directoryManager");
        SecureDirectoryManagerImpl dmImpl = (SecureDirectoryManagerImpl) dm.getDirectoryManagerImpl();
        URI AuthEndpoint;
        Scope scope = Scope.parse(dmImpl.getPropertyString("scope"));
        ClientID clientID = new ClientID(dmImpl.getPropertyString("clientId"));
        URI redirectURI = new URI(getCallbackURL());

        if (dmImpl.getPropertyString("authorizationEndpoint").isEmpty()) {
            OIDCProviderMetadata providerMetadata = IssuerDiscovery();
            AuthEndpoint = providerMetadata.getAuthorizationEndpointURI();
        } else {
            AuthEndpoint = new URI(dmImpl.getPropertyString("authorizationEndpoint"));
        }

        // Build the request
        AuthenticationRequest request = new AuthenticationRequest.Builder(
                new ResponseType(dmImpl.getPropertyString("responseTypes")),
                scope,
                clientID,
                redirectURI)
                .endpointURI(AuthEndpoint)
                .state(state)
                .nonce(nonce)
                .includeGrantedScopes(true)
                .build();

        return request.toURI();
    }

    /**
     * Given an authorization code, calls the auth server to request user info
     *
     * @param accessTokenContent
     * @return
     * @throws URISyntaxException
     * @throws IOException
     */
    public UserInfo getUserInfo(AccessToken accessTokenContent) throws URISyntaxException, IOException {
        DirectoryManagerProxyImpl dm = (DirectoryManagerProxyImpl) AppUtil.getApplicationContext().getBean("directoryManager");
        SecureDirectoryManagerImpl dmImpl = (SecureDirectoryManagerImpl) dm.getDirectoryManagerImpl();
        URI UserInfoEndpoint;
        if (dmImpl.getPropertyString("userinfoEndpoint").isEmpty()) {
            OIDCProviderMetadata providerMetadata = IssuerDiscovery();
            UserInfoEndpoint = providerMetadata.getUserInfoEndpointURI();
        } else {
            UserInfoEndpoint = new URI(dmImpl.getPropertyString("userinfoEndpoint"));
        }
        HTTPResponse httpResponse = new UserInfoRequest(UserInfoEndpoint, (BearerAccessToken) accessTokenContent).toHTTPRequest().send();

        // Parse the response
        UserInfoResponse userInfoResponse = null;
        try {
            userInfoResponse = UserInfoResponse.parse(httpResponse);
        } catch (ParseException ex) {
            LogUtil.error(OpenIDDirectoryManager.class.getName(), ex, "Failed to parse userInfo Response");
            return null;
        }

        if (userInfoResponse != null) {
            if (!userInfoResponse.indicatesSuccess()) {
                LogUtil.error(OpenIDDirectoryManager.class.getName(), null, "The request failed, e.g. due to invalid or expired token");
                return null;
            }
            // Extract the claims
            UserInfo userInfo = userInfoResponse.toSuccessResponse().getUserInfo();
            return userInfo;
        }
        return null;
    }

    /**
     * Given an authorization code, calls the auth server to request a token
     *
     * @param code
     * @param nonce
     * @return
     * @throws URISyntaxException
     * @throws IOException
     */
    public Object[] getTokenForCode(String code, Nonce nonce) throws URISyntaxException, IOException {
        AuthorizationCode authcode = new AuthorizationCode(code);
        URI tokenEndpoint;
        URI jwkSetUri;
        // read from properties
        DirectoryManagerProxyImpl dm = (DirectoryManagerProxyImpl) AppUtil.getApplicationContext().getBean("directoryManager");
        SecureDirectoryManagerImpl dmImpl = (SecureDirectoryManagerImpl) dm.getDirectoryManagerImpl();

        // Construct the code grant from the code obtained from the authz endpoint
        // and the original callback URI used at the authz endpoint
        URI callback = new URI(getCallbackURL());
        AuthorizationGrant codeGrant = new AuthorizationCodeGrant(authcode, callback);

        // The credentials to authenticate the client at the token endpoint
        ClientID clientID = new ClientID(dmImpl.getPropertyString("clientId"));
        Secret clientSecret = new Secret(dmImpl.getPropertyString("clientSecret"));
        ClientAuthentication clientAuth = new ClientSecretBasic(clientID, clientSecret);

        // The token endpoint
        if (dmImpl.getPropertyString("tokenEndpoint").isEmpty()) {
            OIDCProviderMetadata providerMetadata = IssuerDiscovery();
            tokenEndpoint = providerMetadata.getTokenEndpointURI();
            jwkSetUri = providerMetadata.getJWKSetURI();
        } else {
            tokenEndpoint = new URI(dmImpl.getPropertyString("tokenEndpoint"));
            jwkSetUri = new URI(dmImpl.getPropertyString("jsonWebKeySet"));
        }

        // Make the token request
        TokenRequest request = new TokenRequest(tokenEndpoint, clientAuth, codeGrant);

        TokenResponse tokenResponse = null;
        try {
            tokenResponse = OIDCTokenResponseParser.parse(request.toHTTPRequest().send());
        } catch (ParseException | IOException ex) {
            LogUtil.error(OpenIDDirectoryManager.class.getName(), ex, "Error Parsing Token Response");
            return null;
        }

        if (!tokenResponse.indicatesSuccess()) {
            TokenErrorResponse errorResponse = tokenResponse.toErrorResponse();
            LogUtil.error(OpenIDDirectoryManager.class.getName(), null, "Error response:" + errorResponse.getErrorObject().toString() + " : " + errorResponse.getErrorObject().getDescription());
            return null;
        }

        OIDCTokenResponse successResponse = (OIDCTokenResponse) tokenResponse.toSuccessResponse();

        // Get the ID and access token, the server may also return a refresh token
        JWT idToken = successResponse.getOIDCTokens().getIDToken();
        AccessToken accessToken = successResponse.getOIDCTokens().getAccessToken();
        if (successResponse.getOIDCTokens().getRefreshToken() != null) {
            RefreshToken refreshToken = successResponse.getOIDCTokens().getRefreshToken();
        }

        // The required parameters
        Issuer iss = new Issuer(dmImpl.getPropertyString("issuerUrl"));
        JWSAlgorithm jwsAlg = JWSAlgorithm.RS256;
        URL jwkSetURL = jwkSetUri.toURL();

        // Create validator for signed ID tokens
        IDTokenValidator validator = new IDTokenValidator(iss, clientID, jwsAlg, jwkSetURL);

        // Set the expected nonce, leave null if none
        Nonce expectedNonce = nonce; // or null
        ClaimsSet idTokenInfo = null;
        try {
            IDTokenClaimsSet claims = validator.validate(idToken, expectedNonce);
            idTokenInfo = (ClaimsSet) claims;
        } catch (BadJOSEException | JOSEException e) {
            LogUtil.error(OpenIDDirectoryManager.class.getName(), e, "Invalid Claims");
            return null;
        }
        return new Object[]{accessToken, idTokenInfo} ;
    }



    void doLogin(UserInfo userInfo, HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            // read from properties
            DirectoryManagerProxyImpl dm = (DirectoryManagerProxyImpl) AppUtil.getApplicationContext().getBean("directoryManager");
            SecureDirectoryManagerImpl dmImpl = (SecureDirectoryManagerImpl) dm.getDirectoryManagerImpl();

            //String certificate = dmImpl.getPropertyString("certificate");
            boolean userProvisioningEnabled = Boolean.parseBoolean(dmImpl.getPropertyString("userProvisioning"));
            String username;
            if (userInfo.getPreferredUsername() != null) {
                username = userInfo.getPreferredUsername();
            } else {
                username = userInfo.getEmailAddress();
            }

            // get user
            User user = dmImpl.getUserByUsername(username);
            if (user == null && userProvisioningEnabled) {
                // user does not exist, provision
                user = new User();
                user.setId(username);
                user.setUsername(username);
                user.setTimeZone("0");
                user.setActive(1);
                if (userInfo.getEmailAddress() != null && !userInfo.getEmailAddress().isEmpty()) {
                    user.setEmail(userInfo.getEmailAddress());
                }

                if (userInfo.getGivenName() != null && !userInfo.getGivenName().isEmpty()) {
                    user.setFirstName(userInfo.getGivenName());
                }

                if (userInfo.getFamilyName() != null && !userInfo.getFamilyName().isEmpty()) {
                    user.setLastName(userInfo.getFamilyName());
                }

                if (userInfo.getLocale() != null && !userInfo.getLocale().isEmpty()) {
                    user.setLocale(userInfo.getLocale());
                }

                // set role
                RoleDao roleDao = (RoleDao) AppUtil.getApplicationContext().getBean("roleDao");
                Set roleSet = new HashSet();
                Role r = roleDao.getRole("ROLE_USER");
                if (r != null) {
                    roleSet.add(r);
                }
                user.setRoles(roleSet);
                // add user
                UserDao userDao = (UserDao) AppUtil.getApplicationContext().getBean("userDao");
                userDao.addUser(user);
            } else if (user == null && !userProvisioningEnabled) {
                response.sendRedirect(request.getContextPath() + "/web/login?login_error=1");
                return;
            }

            // verify license
            PluginManager pluginManager = (PluginManager) AppUtil.getApplicationContext().getBean("pluginManager");
            DirectoryManagerAuthenticator authenticator = (DirectoryManagerAuthenticator) pluginManager.getPlugin(DirectoryManagerAuthenticatorImpl.class.getName());
            DirectoryManager wrapper = new DirectoryManagerWrapper(dmImpl, true);
            if (user != null) {
                authenticator.authenticate(wrapper, user.getUsername(), user.getPassword());
            }
            // get authorities
            Collection<Role> roles = dm.getUserRoles(username);
            List<GrantedAuthority> gaList = new ArrayList<>();
            if (roles != null && !roles.isEmpty()) {
                for (Role role : roles) {
                    GrantedAuthority ga = new SimpleGrantedAuthority(role.getId());
                    gaList.add(ga);
                }
            }

            // login user
            UserDetails details = new WorkflowUserDetails(user);
            UsernamePasswordAuthenticationToken result = new UsernamePasswordAuthenticationToken(username, "", gaList);
            result.setDetails(details);
            SecurityContextHolder.getContext().setAuthentication(result);

            // add audit trail
            WorkflowHelper workflowHelper = (WorkflowHelper) AppUtil.getApplicationContext().getBean("workflowHelper");
            workflowHelper.addAuditTrail(this.getClass().getName(), "authenticate", "Authentication for user " + username + ": " + true);

            // redirect
            String relayState = request.getParameter("RelayState");
            if (relayState != null && !relayState.isEmpty()) {
                response.sendRedirect(relayState);
            } else {
                SavedRequest savedRequest = new HttpSessionRequestCache().getRequest(request, response);
                String savedUrl = "";
                if (savedRequest != null) {
                    savedUrl = savedRequest.getRedirectUrl();
                } else {
                    savedUrl = request.getContextPath();
                }
                response.sendRedirect(savedUrl);
            }
        } catch (IOException | RuntimeException ex) {
            LogUtil.error(getClass().getName(), ex, "Error in Open ID login");
            request.getSession().setAttribute("SPRING_SECURITY_LAST_EXCEPTION", new Exception(ResourceBundleUtil.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials")));
            String url = request.getContextPath() + "/web/login?login_error=1";
            response.sendRedirect(url);
        }
    }
}
