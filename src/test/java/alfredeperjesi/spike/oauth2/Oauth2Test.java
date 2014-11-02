package alfredeperjesi.spike.oauth2;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import org.hamcrest.CoreMatchers;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.hamcrest.MatcherAssert.assertThat;

public class Oauth2Test {

    private static final String USER_NAME = "";
    private static final String PASSWORD = "";
    private static final String CLIENT_ID = "";
    private static final String ACCESS_TOKEN_URI = "http://localhost:8089/oauth2/token";
    private static final String HTTP_LOCALHOST_8089_PROTECTED = "http://localhost:8089/";
    private static final String HTTP_LOCALHOST_8089_PROTECTED_RESOURCE = HTTP_LOCALHOST_8089_PROTECTED + "protected/resource";
    private static final String PLACEHOLDER_RESOURCE = "%s/protected/resource";
    private static final String PROTECTED_RESOURCE = "protectedResource";
    private static final String INSTANCE_URL = "instance_url";


    @Rule
    public WireMockRule wireMockRuleToken = new WireMockRule(8089);

    private OAuth2Client oauth2Client;

    @Before
    public void setUp() {
        oauth2Client = new OAuth2Client(USER_NAME, PASSWORD, CLIENT_ID, ACCESS_TOKEN_URI);
    }

    @Test
    public void validTokens() {
        stubFor(post(urlEqualTo("/oauth2/token"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"access_token\":\"RsT5OjbzRn430zqMLgV3Ia\", \"expiration\":\"1\", \"token_type\":\"Bearer\", \"refresh_token\":\"null\", \"scope\":\"session\", \"instance_url\":\"http://localhost:8089\"}")));
        stubFor(get(urlEqualTo("/protected/resource"))
//                .withHeader("Accept", equalTo("text/json"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "text/plain")
                        .withBody(PROTECTED_RESOURCE)));

        String result = oauth2Client.get(new OAuth2Client.UrlFormatter() {
            @Override
            public String formatUrl(String url, OAuth2AccessToken template) {
                return String.format(url, template.getAdditionalInformation().get(INSTANCE_URL));

            }
        }, PLACEHOLDER_RESOURCE, String.class);

        assertThat(result, CoreMatchers.equalTo(PROTECTED_RESOURCE));

        verify(postRequestedFor(urlMatching("/oauth2/token"))
                .withHeader("Content-Type", matching("application/x-www-form-urlencoded")));

        verify(getRequestedFor(urlMatching("/protected/resource")));
    }
}
