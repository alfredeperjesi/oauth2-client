package alfredeperjesi.spike.oauth2;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.AccessTokenProviderChain;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.ClientTokenServices;
import org.springframework.security.oauth2.client.token.DefaultAccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

import java.util.Arrays;

public class OAuth2Client {

    private final String userName;
    private final String password;
    private final String clientId;
    private final String accessTokenUri;
    private final AccessTokenRequest accessTokenRequest;

    public OAuth2Client(final String userName, final String password, final String clientId, final String accessTokenUri) {
        this.userName = userName;
        this.password = password;
        this.clientId = clientId;
        this.accessTokenUri = accessTokenUri;
        this.accessTokenRequest = new DefaultAccessTokenRequest();
    }

    public <T> T get(UrlFormatter urlFormatter, String url, Class<T> responseClass) {
        try {
            OAuth2RestTemplate template = new OAuth2RestTemplate(resource(), new DefaultOAuth2ClientContext(accessTokenRequest));
            AccessTokenProviderChain provider = new AccessTokenProviderChain(Arrays.asList(new AuthorizationCodeAccessTokenProvider()));
            provider.setClientTokenServices(clientTokenServices());
            template.setRetryBadAccessTokens(true);
            return template.getForEntity(urlFormatter.formatUrl(url, template.getAccessToken()), responseClass).getBody();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private ClientTokenServices clientTokenServices() {
        return new ClientTokenServices() {

            private OAuth2AccessToken oAuth2AccessToken;

            @Override
            public OAuth2AccessToken getAccessToken(OAuth2ProtectedResourceDetails resource, Authentication authentication) {
                return oAuth2AccessToken;
            }

            @Override
            public void saveAccessToken(OAuth2ProtectedResourceDetails resource, Authentication authentication, OAuth2AccessToken accessToken) {
                this.oAuth2AccessToken = oAuth2AccessToken;
                System.out.println("ClientTokenServices saved " + accessToken.getValue());
            }

            @Override
            public void removeAccessToken(OAuth2ProtectedResourceDetails resource, Authentication authentication) {
                this.oAuth2AccessToken = null;
            }
        };
    }

    private OAuth2ProtectedResourceDetails resource() {
        ResourceOwnerPasswordResourceDetails resourceOwnerPasswordResourceDetails = new ResourceOwnerPasswordResourceDetails();
        resourceOwnerPasswordResourceDetails.setAccessTokenUri(accessTokenUri);
        resourceOwnerPasswordResourceDetails.setClientId(clientId);
        resourceOwnerPasswordResourceDetails.setUsername(userName);
        resourceOwnerPasswordResourceDetails.setPassword(password);
        return resourceOwnerPasswordResourceDetails;
    }

    public static interface UrlFormatter {
        String formatUrl(String url, OAuth2AccessToken template);
    }
}
