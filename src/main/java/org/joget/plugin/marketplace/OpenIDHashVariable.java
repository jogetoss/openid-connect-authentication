package org.joget.plugin.marketplace;

import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collection;
import org.joget.apps.app.model.DefaultHashVariablePlugin;
import org.joget.apps.app.service.AppUtil;
import org.joget.commons.util.LogUtil;
import org.joget.directory.dao.UserMetaDataDao;
import org.joget.directory.model.UserMetaData;
import org.joget.directory.model.service.DirectoryManagerProxyImpl;
import org.joget.plugin.directory.SecureDirectoryManagerImpl;
import org.joget.workflow.model.service.WorkflowUserManager;
import org.springframework.context.ApplicationContext;

public class OpenIDHashVariable extends DefaultHashVariablePlugin {

    @Override
    public String getName() {
        return "OpenID Connect Hash Variable";
    }

    @Override
    public String getVersion() {
        return "7.0.7";
    }

    @Override
    public String getDescription() {
        return "Hash Variable to refresh OpenID Connect access token using refresh token";
    }

    @Override
    public String getPrefix() {
        return "oidc";
    }

    @Override
    public String processHashVariable(String variableKey) {
        ApplicationContext appContext = AppUtil.getApplicationContext();
        WorkflowUserManager workflowUserManager = (WorkflowUserManager) appContext.getBean("workflowUserManager");

        String username = workflowUserManager.getCurrentUsername();

        if (WorkflowUserManager.ROLE_ANONYMOUS.equals(username)) {
            return "";
        }

        if ("refreshAccessToken".equals(variableKey)) {
            DirectoryManagerProxyImpl dm = (DirectoryManagerProxyImpl) AppUtil.getApplicationContext().getBean("directoryManager");
            SecureDirectoryManagerImpl dmImpl = (SecureDirectoryManagerImpl) dm.getDirectoryManagerImpl();

            UserMetaDataDao userMetaDataDao = (UserMetaDataDao) AppUtil.getApplicationContext().getBean("userMetaDataDao");

            //String accessTokenUserMetaKey = dmImpl.getPropertyString("accessTokenUserMetaKey").isEmpty() ? OpenIDDirectoryManager.DEFAULT_USER_META_ACCESS_TOKEN_KEY : dmImpl.getPropertyString("accessTokenUserMetaKey");
            //String refreshTokenUserMetaKey = dmImpl.getPropertyString("refreshTokenUserMetaKey").isEmpty() ? OpenIDDirectoryManager.DEFAULT_USER_META_REFRESH_TOKEN_KEY : dmImpl.getPropertyString("refreshTokenUserMetaKey");
            
            UserMetaData accessTokenUmd = userMetaDataDao.getUserMetaData(username, OpenIDDirectoryManager.DEFAULT_USER_META_ACCESS_TOKEN_KEY);
            UserMetaData refreshTokenUmd = userMetaDataDao.getUserMetaData(username, OpenIDDirectoryManager.DEFAULT_USER_META_REFRESH_TOKEN_KEY);

            //check current access token expiry
            if (accessTokenUmd != null) {
                try {
                    JWSObject token = (JWSObject) JWTParser.parse(accessTokenUmd.getValue());
                    Payload payload = token.getPayload();

                    Long timeNow = System.currentTimeMillis() / 1000L;
                    Long tokenExp = (Long) payload.toJSONObject().getAsNumber("exp");

                    if (timeNow < tokenExp) {
                        LogUtil.info(this.getClassName(), "current access token is still valid");
                        return accessTokenUmd.getValue();
                    }

                } catch (Exception e) {
                    LogUtil.error(this.getClassName(), e, "error parsing access token");
                }
            }
            
            //if there's no refresh token
            if (refreshTokenUmd == null) {
                LogUtil.info(this.getClassName(), "no refresh token in user meta");
                return accessTokenUmd != null ? accessTokenUmd.getValue() : "";
            }

            LogUtil.info(this.getClassName(), "attempting to get new tokens with refresh token...");

            try {
                RefreshToken receivedRefreshToken = new RefreshToken(refreshTokenUmd.getValue());
                AuthorizationGrant refreshTokenGrant = new RefreshTokenGrant(receivedRefreshToken);
                //URI tokenEndpoint = new URI(dmImpl.getPropertyString("tokenEndpoint"));
                URI tokenEndpoint;
                
                if (dmImpl.getPropertyString("tokenEndpoint").isEmpty()) {
                    OIDCProviderMetadata providerMetadata = OpenIDDirectoryManager.IssuerDiscovery();
                    tokenEndpoint = providerMetadata.getTokenEndpointURI();
                } else {
                    tokenEndpoint = new URI(dmImpl.getPropertyString("tokenEndpoint"));
                }
                
                ClientID clientID = new ClientID(dmImpl.getPropertyString("clientId"));
                Secret secret = new Secret(dmImpl.getPropertyString("clientSecret"));
                ClientAuthentication clientAuth = new ClientSecretBasic(clientID, secret);

                TokenRequest request = new TokenRequest(tokenEndpoint, clientAuth, refreshTokenGrant);
                TokenResponse tokenResponse = OIDCTokenResponseParser.parse(request.toHTTPRequest().send());
                
                if (!tokenResponse.indicatesSuccess()) {
                    TokenErrorResponse errorResponse = tokenResponse.toErrorResponse();
                    LogUtil.error(this.getClassName(), null, "Error response: " + errorResponse.getErrorObject().toString() + " : " + errorResponse.getErrorObject().getDescription());
                    return accessTokenUmd != null ? accessTokenUmd.getValue() : "";
                }
                
                AccessTokenResponse successResponse = tokenResponse.toSuccessResponse();
                Tokens tokens = successResponse.getTokens();
                AccessToken accessToken = tokens.getAccessToken();
                RefreshToken refreshToken = tokens.getRefreshToken();

                //save tokens to user meta
                if ("true".equals(dmImpl.getPropertyString("saveAccessToken"))) {
                    if (accessToken != null) {
                        UserMetaData umd = userMetaDataDao.getUserMetaData(username, OpenIDDirectoryManager.DEFAULT_USER_META_ACCESS_TOKEN_KEY);
                        if (umd == null) {
                            umd = new UserMetaData();
                            umd.setUsername(username);
                            umd.setKey(OpenIDDirectoryManager.DEFAULT_USER_META_ACCESS_TOKEN_KEY);
                            umd.setValue(accessToken.getValue());
                            userMetaDataDao.addUserMetaData(umd);
                        } else {
                            umd.setValue(accessToken.getValue());
                            userMetaDataDao.updateUserMetaData(umd);
                        }
                    }

                    if (refreshToken != null) {
                        UserMetaData umd = userMetaDataDao.getUserMetaData(username, OpenIDDirectoryManager.DEFAULT_USER_META_REFRESH_TOKEN_KEY);
                        if (umd == null) {
                            umd = new UserMetaData();
                            umd.setUsername(username);
                            umd.setKey(OpenIDDirectoryManager.DEFAULT_USER_META_REFRESH_TOKEN_KEY);
                            umd.setValue(refreshToken.getValue());
                            userMetaDataDao.addUserMetaData(umd);
                        } else {
                            umd.setValue(refreshToken.getValue());
                            userMetaDataDao.updateUserMetaData(umd);
                        }
                    }
                }

                if (accessToken != null) {
                    LogUtil.info(this.getClassName(), "access token successfully refreshed");
                    return accessToken.getValue();
                } else {
                    return accessTokenUmd != null ? accessTokenUmd.getValue() : "";
                }

            } catch (Exception e) {
                LogUtil.error(this.getClassName(), e, "error getting access token");
                return "";
            }
        }

        return null;
    }

    @Override
    public String getLabel() {
        return "OpenID Connect Hash Variable";
    }

    @Override
    public String getClassName() {
        return this.getClass().getName();
    }

    @Override
    public String getPropertyOptions() {
        return "";
    }

    @Override
    public Collection<String> availableSyntax() {
        Collection<String> syntax = new ArrayList<String>();
        syntax.add("oidc.refreshAccessToken");

        return syntax;
    }
}
