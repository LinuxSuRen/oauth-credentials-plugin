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

import com.cloudbees.plugins.credentials.CredentialsDescriptor;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.DescriptorExtensionList;
import hudson.Extension;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.model.RootAction;
import hudson.util.HttpResponses;
import hudson.util.ListBoxModel;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;

import javax.servlet.ServletException;
import java.io.IOException;
import java.util.List;
import java.util.Random;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;

public class OAuth2Token extends BaseStandardCredentials {

    @NonNull
    private final String clientId;

    @CheckForNull
    private final String name;

    @CheckForNull
    private final Secret token;

    private transient boolean valid;

    private transient long nextValidCheck;

    private transient OAuth2Client client;

    @DataBoundConstructor
    public OAuth2Token(@CheckForNull String id, @CheckForNull String description, @CheckForNull String clientId,
                       @CheckForNull String name, @CheckForNull String token) {
        super(id, description);
        this.clientId = StringUtils.defaultString(clientId);
        this.name = Util.fixEmpty(name);
        this.token = StringUtils.isBlank(token) ? null : Secret.fromString(token);
    }

    @NonNull
    public String getClientId() {
        return clientId;
    }

    @CheckForNull
    public Secret getToken() {
        return token;
    }

    @CheckForNull
    public String getName() {
        return name;
    }

    public boolean isMissingToken() {
        return token == null || StringUtils.isBlank(token.getPlainText());
    }

    public OAuth2Client getClient() {
        return Jenkins.getInstance().getDescriptorByType(DescriptorImpl.class).lookupClient(this);
    }

    public synchronized boolean isValid() {
        if (isMissingToken()) {
            return false;
        }
        OAuth2Client client = getClient();
        if (client == null) {
            return false;
        }
        if (nextValidCheck < System.currentTimeMillis()) {
            if (nextValidCheck == 0) {
                // on start-up we will defer the initial check for a portion of time to prevent blocking the UI
                // all at once
                valid = true;
                nextValidCheck = System.currentTimeMillis() + new Random().nextInt(360000);
            } else {
                try {
                    client.validateToken(token);
                    valid = true;
                } catch (Throwable t) {
                    valid = false;
                }
                nextValidCheck = System.currentTimeMillis() + (86400000 / 2) + new Random().nextInt(86400000);
            }
        }
        return valid;
    }

    @Extension
    public static class DescriptorImpl extends CredentialsDescriptor {

        private List<OAuth2Client> clients = new CopyOnWriteArrayList<OAuth2Client>();

        public DescriptorImpl() {
            load();
        }

        public List<OAuth2Client> getClients() {
            return clients;
        }

        public ListBoxModel doFillClientIdItems() {
            ListBoxModel result = new ListBoxModel();
            for (OAuth2Client client : clients) {
                result.add(client.getName(), client.getClientId());
            }
            return result;
        }

        public OAuth2Client lookupClient(OAuth2Token token) {
            if (token != null) {
                return lookupClient(token.getClientId());
            }
            return null;
        }

        private OAuth2Client lookupClient(String clientId) {
            for (OAuth2Client c : clients) {
                if (StringUtils.equals(c.getClientId(), clientId)) {
                    return c;
                }
            }
            return null;
        }

        @Override
        public String getDisplayName() {
            return "OAuth 2.0 Token";
        }

        public DescriptorExtensionList<OAuth2Client, Descriptor<OAuth2Client>> getClientDescriptors() {
            return Jenkins.getInstance().getDescriptorList(OAuth2Client.class);
        }

        @Override
        public boolean configure(StaplerRequest req, JSONObject json) throws FormException {
            clients.clear();
            if (json.has("clients")) {
                clients.addAll(req.bindJSONToList(OAuth2Client.class, json.get("clients")));
            }
            save();
            return super.configure(req, json);
        }

        public HttpResponse doAuthenticate(StaplerRequest req, @QueryParameter String clientId,
                                           @QueryParameter String authId, @QueryParameter boolean force) {
            if (StringUtils.isBlank(authId) || StringUtils.isBlank(clientId)) {
                return HttpResponses.error(400, "Bad Request");
            }
            OAuth2Client client = lookupClient(clientId);
            if (client == null) {
                return HttpResponses.notFound();
            }
            return HttpResponses.redirectTo(client.buildAuthenticationUrl(OAuth2CallbackAction.getCallbackUrl()
                    + "/client/" + Util.rawEncode(clientId), authId, force));
        }


    }

    @Extension
    public static class OAuth2CallbackAction implements RootAction {

        public static final String URL_NAME = "oauth2callback";

        public String getIconFileName() {
            return null;
        }

        public String getDisplayName() {
            return null;
        }

        public String getUrlName() {
            return URL_NAME;
        }

        public Client getClient(String clientId) {
            DescriptorImpl descriptor = Jenkins.getInstance().getDescriptorByType(DescriptorImpl.class);
            OAuth2Client client = descriptor.lookupClient(clientId);
            return client == null ? null : new Client(client);
        }

        public static String getCallbackUrl() {
            return Jenkins.getInstance().getRootUrlFromRequest() + URL_NAME;
        }
    }

    public static class Client {
        private final OAuth2Client client;

        public Client(OAuth2Client client) {
            this.client = client;
        }

        public HttpResponse doIndex(StaplerRequest request,
                                    @QueryParameter String state,
                                    @QueryParameter String code) throws IOException, ServletException {
            return HttpResponses.forwardToView(
                    new Callback(client.validateCode(OAuth2CallbackAction.getCallbackUrl() + "/client/" + client.getClientId(), state, code), client.getClientId(),
                            state),
                    "index");
        }

    }

    public static class Callback {

        private final OAuth2Client.TokenResponse token;

        private final String authId;

        private final String clientId;

        public Callback(OAuth2Client.TokenResponse token, String clientId, String authId) {
            this.token = token;
            this.authId = authId;
            this.clientId = clientId;
        }

        public OAuth2Client.TokenResponse getToken() {
            return token;
        }

        public String getAuthId() {
            return authId;
        }

        public String getClientId() {
            return clientId;
        }
    }


}
