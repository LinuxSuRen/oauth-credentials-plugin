/*
 * The MIT License
 *
 * Copyright (c) 2011-2013, CloudBees, Inc., Stephen Connolly.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package com.cloudbees.plugins.credentials.oauth;

import hudson.model.AbstractDescribableImpl;
import hudson.util.Secret;
import net.sf.json.JSONObject;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.DataBoundConstructor;

import java.io.IOException;
import java.io.Serializable;
import java.util.Set;
import java.util.TreeSet;

public abstract class OAuth2Client extends AbstractDescribableImpl<OAuth2Client> implements Serializable {

    private final String name;

    private final String clientId;

    private final Secret clientSecret;

    private final Set<String> scopes;

    @DataBoundConstructor
    public OAuth2Client(String name, String clientId, String clientSecret, JSONObject scopes) {
        this.name = name;
        this.clientId = clientId;
        this.scopes = new TreeSet<String>();
        if (scopes != null) {
            for (Object scope : scopes.keySet()) {
                if (scope instanceof String && scopes.getBoolean((String) scope)) {
                    this.scopes.add((String) scope);
                }
            }
        }
        this.clientSecret = Secret.fromString(clientSecret);
    }

    public String getName() {
        return name;
    }

    public String getClientId() {
        return clientId;
    }

    public Secret getClientSecret() {
        return clientSecret;
    }

    public Set<String> getScopes() {
        return scopes;
    }

    public String getScopeString() {
        return StringUtils.join(scopes, ",");
    }

    public abstract String buildAuthenticationUrl(String callbackUrl, String state, boolean force);

    public abstract TokenResponse validateCode(String callbackUrl, String state, String code);

    public abstract void validateToken(Secret token) throws IOException;

    public static class TokenResponse {
        private final Secret token;
        private final String name;

        public TokenResponse(String name, String token) {
            this.name = name;
            this.token = Secret.fromString(token);
        }

        public String getName() {
            return name;
        }

        public Secret getToken() {
            return token;
        }
    }
}
