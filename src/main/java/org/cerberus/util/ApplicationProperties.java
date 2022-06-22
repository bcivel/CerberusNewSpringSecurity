/**
 * Cerberus Copyright (C) 2013 - 2017 cerberustesting
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This file is part of Cerberus.
 *
 * Cerberus is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Cerberus is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Cerberus.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.cerberus.util;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;


/**
 *
 * @author bcivel
 */
@Component
public class ApplicationProperties {
    
    public static final String AUTHENTICATION_VALUE_KEYCLOAK = "keycloak";
    
    private static String authentication;
    private static String env;
    private static String saas;
    private static String saasInstance;
    private static String keycloakRealm;
    private static String keycloakUrl;
    private static String keycloakClient;
    private static String securePublicApi;
    
    @Value("${cerberus.authentication}")
    public void setAuthentication(String value) {
        this.authentication = value;
    }
    
    @Value("${cerberus.environment}")
    public void setEnvironment(String value) {
        this.env = value;
    }
    
    @Value("${cerberus.saas}")
    public void setSaaS(String value) {
        this.saas = value;
    }
    
    @Value("${cerberus.saas.instance}")
    public void setSaaSInstance(String value) {
        this.saasInstance = value;
    }
    
    @Value("${keycloak.realm}")
    public void setKeycloakRealm(String value) {
        this.keycloakRealm = value;
    }
    
    @Value("${keycloak.url}")
    public void setKeycloakUrl(String value) {
        this.keycloakUrl = value;
    }
    
    @Value("${keycloak.client}")
    public void setKeycloakClient(String value) {
        this.keycloakClient = value;
    }
   
    @Value("${cerberus.secure-public-api}")
    public void setSecurePublicApi(String value) {
        this.securePublicApi = value;
    }
    
    public boolean isSecurePublicApi() {
        return (("true".equals(securePublicApi)) || ("1".equals(securePublicApi)));
    }
   
    public boolean isKeycloak() {
        return (AUTHENTICATION_VALUE_KEYCLOAK.equals(authentication));
    }

    public boolean isSaaS() {
        return (("true".equals(saas)) || ("1".equals(saas)));
    }

    public String getAuthentication() {
        return authentication;
    }

    public String getEnv() {
        return env;
    }

    public String getSaas() {
        return saas;
    }

    public String getSaasInstance() {
        return saasInstance;
    }

    public String getKeycloakRealm() {
        return keycloakRealm;
    }

    public String getKeycloakUrl() {
        return keycloakUrl;
    }

    public String getKeycloakClient() {
        return keycloakClient;
    }

    public String getSecurePublicApi() {
        return securePublicApi;
    }
    
    
}
