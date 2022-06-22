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
package org.cerberus.controller;

import javax.servlet.http.HttpServletRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.cerberus.crud.entity.TestCaseExecution;
import org.cerberus.util.ApplicationProperties;
import org.json.JSONException;
import org.json.JSONObject;
import org.owasp.html.PolicyFactory;
import org.owasp.html.Sanitizers;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 *
 * @author bcivel
 */
@RestController
@RequestMapping("/information")
public class CerberusController {

    private static final Logger LOG = LogManager.getLogger(TestCaseExecution.class);
    private final PolicyFactory policy = Sanitizers.FORMATTING.and(Sanitizers.LINKS);

    @Autowired
    ApplicationProperties applicationProperties;

    @GetMapping("/authenticationMode")
    public String create(String test, String active, String parentTest, String description,
            HttpServletRequest request) {

        JSONObject jsonResponse = new JSONObject();

        try {
            jsonResponse.put("isKeycloak", applicationProperties.isKeycloak());
            jsonResponse.put("keycloakClient", applicationProperties.getKeycloakClient());
            jsonResponse.put("keycloakRealm", applicationProperties.getKeycloakRealm());
            jsonResponse.put("keycloakUrl", applicationProperties.getKeycloakUrl());
        } catch (JSONException ex) {
            LOG.warn(ex);
        }
        return jsonResponse.toString();
    }

}
