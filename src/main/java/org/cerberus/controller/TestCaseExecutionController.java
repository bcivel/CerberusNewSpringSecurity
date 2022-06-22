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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.cerberus.crud.entity.TestCaseExecution;
import org.cerberus.crud.service.impl.TestCaseExecutionService;
import org.cerberus.exception.CerberusException;
import org.json.JSONArray;
import org.owasp.html.PolicyFactory;
import org.owasp.html.Sanitizers;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 *
 * @author bcivel
 */
@RestController
@RequestMapping("/testcaseexecution")
public class TestCaseExecutionController {

    private static final Logger LOG = LogManager.getLogger(TestCaseExecution.class);
    private final PolicyFactory policy = Sanitizers.FORMATTING.and(Sanitizers.LINKS);
    
    @Autowired
    TestCaseExecutionService testCaseExecutionService;

    @GetMapping("/getLastByCriteria")
    public String getLastByCriteria(
            @RequestParam(name = "test", value="test") String test, 
            @RequestParam(name = "testCase", value="testCase") String testCase,
            @RequestParam(name = "numberOfExecution", required = false) Integer numberOfExecution, 
            @RequestParam(name = "tag", required = false) String tag,
            @RequestParam(name = "campaign", required = false) String campaign) {
        
        try {
            test = policy.sanitize(test);
            testCase = policy.sanitize(testCase);
            tag = policy.sanitize(tag);
            campaign = policy.sanitize(campaign);
            
            JSONArray ja = testCaseExecutionService.getLastByCriteria(test, testCase, tag, campaign, numberOfExecution);
            return ja.toString();
        } catch (CerberusException ex) {
            LOG.warn(ex);
            return "error";
        }
    }

    @GetMapping("/toto")
    public String toto() {
        return "it works too";
    }
}
