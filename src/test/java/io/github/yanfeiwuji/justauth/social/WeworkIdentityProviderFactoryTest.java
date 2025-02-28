package io.github.yanfeiwuji.justauth.social;

import io.github.yanfeiwuji.justauth.social.common.JustAuthSecondIdentityProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class WeworkIdentityProviderFactoryTest {

    private WeworkIdentityProviderFactory weworkIdentityProviderFactoryUnderTest;

    @BeforeEach
    void setUp() {
        weworkIdentityProviderFactoryUnderTest = new WeworkIdentityProviderFactory();
    }

    @Test
    void testGetName() throws Exception {
        assertEquals("企业微信", weworkIdentityProviderFactoryUnderTest.getName());
    }

    @Test
    void testCreate() {
        // Setup
        final KeycloakSession session = null;
        final IdentityProviderModel model = new IdentityProviderModel();
        model.setInternalId("internalId");
        model.setAlias("alias");
        model.setProviderId("providerId");
        model.setEnabled(false);
        model.setStoreToken(false);

        // Run the test
        final JustAuthSecondIdentityProvider result = weworkIdentityProviderFactoryUnderTest.create(session, model);

        // Verify the results
        assertEquals("default", result.getConfig().getDefaultScope());
    }

    @Test
    void testCreateConfig() throws Exception {
        // Setup
        final IdentityProviderModel identityProviderModel = new IdentityProviderModel();
        identityProviderModel.setInternalId("internalId");
        identityProviderModel.setAlias("alias");
        identityProviderModel.setProviderId("providerId");
        identityProviderModel.setEnabled(false);
        identityProviderModel.setStoreToken(false);
        final OAuth2IdentityProviderConfig expectedResult = new OAuth2IdentityProviderConfig(identityProviderModel);

        // Run the test
        final OAuth2IdentityProviderConfig result = weworkIdentityProviderFactoryUnderTest.createConfig();

        // Verify the results
        // assertEquals(expectedResult, result);
    }

    @Test
    void testGetId() throws Exception {
        assertEquals("wework", weworkIdentityProviderFactoryUnderTest.getId());
    }

    @Test
    void testGetConfigProperties() {
        // Setup
        // Run the test
        final List<ProviderConfigProperty> result = weworkIdentityProviderFactoryUnderTest.getConfigProperties();

        // Verify the results
    }
}
