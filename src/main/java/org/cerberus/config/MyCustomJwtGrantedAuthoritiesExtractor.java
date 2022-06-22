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
package org.cerberus.config;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;

@Component
public class MyCustomJwtGrantedAuthoritiesExtractor implements Converter<Jwt, Collection<GrantedAuthority>> {

    private static final String ROLEPREFIX = "ROLE_";
    private static final String KEYCLOAKCLIENT = "Cerberus-SpringBoot";
    private static final Logger LOG = LogManager.getLogger(MyCustomJwtGrantedAuthoritiesExtractor.class);

    public Collection<GrantedAuthority> convert(final Jwt jwt) {
        LOG.warn("Get Keycloak Roles");
        //final Map<String, Object> realmAccess =
        //        (Map<String, Object>) jwt.getClaims().get("resource_access");
        LOG.warn(jwt.toString());

        final Map<String, Object> realmAccess =
                (Map<String, Object>) jwt.getClaims().get("realm_access");
        //Map<String, Object> phoenixPimp = (Map<String, Object>) realmAccess.get(KEYCLOAKCLIENT);
        //if (null == phoenixPimp) phoenixPimp = new HashMap<>();
        //List<String> extractedRoles = ((List<String>) phoenixPimp.get("roles"));
        List<String> extractedRoles = ((List<String>) realmAccess.get("roles"));
        List<String> roles = new ArrayList<>();
        if (!CollectionUtils.isEmpty(extractedRoles)) {
            roles.addAll(extractedRoles);
        }

        LOG.warn(roles.toString());
        //Ajout d'un role par défaut
        //roles.add("TEST_DEFAULT");
        return roles
                .stream()
                .map(roleName -> ROLEPREFIX + roleName)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }
}
