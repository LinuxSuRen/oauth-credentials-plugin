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
package com.cloudbees.plugins.credentials.oauth.impl;

import com.cloudbees.plugins.credentials.oauth.OAuth2Client;
import com.cloudbees.plugins.credentials.oauth.OAuth2ClientDescriptor;
import hudson.Extension;
import hudson.util.Secret;
import net.sf.json.JSONObject;
import org.kohsuke.github.GHMyself;
import org.kohsuke.github.GitHub;
import org.kohsuke.stapler.DataBoundConstructor;
import org.scribe.builder.ServiceBuilder;
import org.scribe.builder.api.DefaultApi20;
import org.scribe.model.OAuthConfig;
import org.scribe.model.Token;
import org.scribe.model.Verifier;
import org.scribe.oauth.OAuthService;
import org.scribe.utils.OAuthEncoder;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.logging.Logger;

public class GitHubOAuth2Client extends OAuth2Client {
    private static final Logger LOGGER = Logger.getLogger(GitHubOAuth2Client.class.getName());

    @DataBoundConstructor
    public GitHubOAuth2Client(String name, String clientId, String clientSecret, JSONObject scopes) {
        super(name, clientId, clientSecret, scopes);
    }

    private synchronized OAuthService getService(String callbackUrl) {
        return new ServiceBuilder()
                .provider(GitHubApi.class)
                .callback(callbackUrl)
                .scope(getScopeString())
                .apiKey(getClientId())
                .apiSecret(getClientSecret().getPlainText())
                .build();
    }

    @Override
    public String buildAuthenticationUrl(String callbackUrl, String state, boolean force) {
        StringBuilder url = new StringBuilder(getService(callbackUrl).getAuthorizationUrl(null));
        if (state != null) {
            url.append("&state=").append(OAuthEncoder.encode(state));
        }
        if (force) {
            url.append("&force=true");
        }
        return url.toString();
    }

    @Override
    public TokenResponse validateCode(String callbackUrl, String state, String code) {
        Verifier verifier = new Verifier(code);
        Token accessToken = getService(callbackUrl).getAccessToken(null, verifier);
        try {
            GitHub gitHub = GitHub.connectUsingOAuth(accessToken.getToken());
            GHMyself myself = gitHub.getMyself();
            return new TokenResponse(myself.getLogin(), accessToken.getToken());
        } catch (IOException e) {
            return null;
        }
    }

    @Override
    public void validateToken(Secret token) throws IOException {
        GitHub gitHub = GitHub.connectUsingOAuth(token.getPlainText());
        GHMyself myself = gitHub.getMyself();
    }

    @Override
    public DescriptorImpl getDescriptor() {
        return (DescriptorImpl) super.getDescriptor();
    }

    @Extension
    public static class DescriptorImpl extends OAuth2ClientDescriptor {

        @Override
        public String getDisplayName() {
            return "GitHub";
        }

        @Override
        public Map<String, String> getScopes() {
            Map<String, String> r = new LinkedHashMap<String, String>();
            r.put("user", "Read/write access to profile information");
            r.put("user:email", "Read access to a user's email addresses");
            r.put("user:follow", "Access to follow or unfollow other users");
            r.put("public_repo", "Read/write access to public repositories and organizations");
            r.put("repo", "Read/write access to public and private repositories and organiztions");
            r.put("repo:status", "Read/write access to public and private respository commit statuses");
            r.put("delete_repo", "Delete access to adminable repositories");
            r.put("gist", "Write access to gists");
            return r;
        }
    }

    public static class GitHubApi extends DefaultApi20 {
        private static final String AUTHORIZE_URL =
                "https://github.com/login/oauth/authorize?client_id=%s&redirect_uri=%s";
        private static final String SCOPED_AUTHORIZE_URL = AUTHORIZE_URL + "&scope=%s";

        @Override
        public String getAccessTokenEndpoint() {
            return "https://github.com/login/oauth/access_token";
        }

        @Override
        public String getAuthorizationUrl(OAuthConfig config) {
            StringBuilder result = new StringBuilder("https://github.com/login/oauth/authorize");
            result.append("?client_id=").append(OAuthEncoder.encode(config.getApiKey()));
            if (config.getCallback() != null) {
                result.append("&redirect_uri=").append(OAuthEncoder.encode(config.getCallback()));
            }
            if (config.hasScope()) {
                result.append("&scope=").append(OAuthEncoder.encode(config.getScope()));
            }
            return result.toString();
        }
    }
}
