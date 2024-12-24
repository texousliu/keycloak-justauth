package io.github.yanfeiwuji.justauth.social.common;

import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.request.AuthDefaultRequest;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

import java.util.function.Function;

/**
 * @author yanfeiwuji
 * @since 2021/1/12 7:53 下午
 */
public class JustAuthIdentityProviderConfig extends OAuth2IdentityProviderConfig {

    private static final String AGENT_ID_KEY = "weworkAgentId";
    private static final String ALIPAY_PUBLIC_KEY = "alipayPublicKey";
    private static final String CODING_GROUP_NAME = "codingGroupName";

    private final JustAuthKey justAuthKey;
    private final Function<AuthConfig, AuthDefaultRequest> authToReqFunc;

    public JustAuthIdentityProviderConfig(IdentityProviderModel model,
                                          JustAuthKey justAuthKey,
                                          Function<AuthConfig, AuthDefaultRequest> authToReqFunc) {
        super(model);
        this.justAuthKey = justAuthKey;
        this.authToReqFunc = authToReqFunc;

    }

    public JustAuthKey getJustAuthKey() {
        return this.justAuthKey;
    }

    public String getAgentId() {
        return getConfig().get(AGENT_ID_KEY);
    }

    public void setAgentId(String agentId) {
        getConfig().put(AGENT_ID_KEY, agentId);
    }

    public String getAlipayPublicKey() {
        return getConfig().get(ALIPAY_PUBLIC_KEY);
    }

    public void setAlipayPublicKey(String alipayPublicKey) {
        getConfig().put(ALIPAY_PUBLIC_KEY, alipayPublicKey);
    }

    public String getCodingGroupName() {
        return getConfig().get(CODING_GROUP_NAME);
    }

    public void setCodingGroupName(String codingGroupName) {
        getConfig().put(CODING_GROUP_NAME, codingGroupName);
    }

    public Function<AuthConfig, AuthDefaultRequest> getAuthToReqFunc() {
        return authToReqFunc;
    }
}
