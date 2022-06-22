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

import javax.sql.DataSource;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.MessageDigestPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;

/**
 *
 * @author bcivel
 */
@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    private static final Logger LOG = LogManager.getLogger(SecurityConfiguration.class);

    private static final String SECURED_PATH = "/screenrecorder/**";
    public static final String AUTHENTICATION_VALUE_KEYCLOAK = "keycloak";

    private static boolean isKeycloak;

    @Value("${cerberus.authentication}")
    public void setAuthentication(String value) {
        this.isKeycloak = AUTHENTICATION_VALUE_KEYCLOAK.equals(value);
    }

    private static boolean isSecurePublicApi;

    @Value("${cerberus.secure-public-api}")
    public void setSecurePublicApi(String value) {
        this.isSecurePublicApi = ("true".equals(value)) || ("1".equals(value));
    }

    private static String issuerUri;

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    public void setIssuerUri(String value) {
        this.issuerUri = value;
    }

    private static String jwkSetUri;

    @Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}")
    public void setJwkSetUri(String value) {
        this.jwkSetUri = value;
    }

    @Autowired
    private DataSource dataSource;
    @Autowired
    private MyCustomJwtGrantedAuthoritiesExtractor myCustomJwtGrantedAuthoritiesExtractor;

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        LOG.info("Starting with keycloack authentication : " + isKeycloak);
        LOG.info("Starting with secured public api : " + isSecurePublicApi);

        http.authorizeRequests()
                /**
                 * TestRO
                 */
                .antMatchers("/TestCaseExecution.jsp").hasRole("TestRO")
                .antMatchers("/TestCaseExecutionList.jsp").hasRole("TestRO")
                .antMatchers("/ReportingExecutionByTag.jsp").hasRole("TestRO")
                .antMatchers("/ReportingExecutionOverTime.jsp").hasRole("TestRO")
                .antMatchers("/ReportingCampaignOverTime.jsp").hasRole("TestRO")
                .antMatchers("/TestCaseExecutionQueueList.jsp").hasRole("TestRO")
                .antMatchers("/Test.jsp").hasRole("TestRO")
                .antMatchers("/TestCaseScript.jsp").hasRole("TestRO")
                .antMatchers("/TestCaseList.jsp").hasRole("TestRO")
                .antMatchers("/CampaignList.jsp").hasRole("TestRO")
                .antMatchers("/ManageExecutionPool").hasRole("TestRO")
                .antMatchers("/ReadExecutionPool").hasRole("TestRO")
                .antMatchers("/ReadExecutionPools").hasRole("TestRO")
                .antMatchers("/GetTestCaseList").hasRole("TestRO")
                .antMatchers("/ReadTestCaseExecutionMedia").hasRole("TestRO")
                .antMatchers("/GetTestCase").hasRole("TestRO")
                .antMatchers("/TestcaseList").hasRole("TestRO")
                .antMatchers("/GetDataForTestCaseSearch").hasRole("TestRO")
                .antMatchers("/TCEwwwDetail").hasRole("TestRO")
                .antMatchers("/GenerateGraph").hasRole("TestRO")
                .antMatchers("/TestCaseActionExecutionDetail").hasRole("TestRO")
                .antMatchers("/ExecutionPerBuildRevision").hasRole("TestRO")
                .antMatchers("/GetStepUsedAsLibraryInOtherTestCasePerApplication").hasRole("TestRO")
                .antMatchers("/ExportTestCase").hasRole("TestRO")
                .antMatchers("/FindTestImplementationStatusPerApplication").hasRole("TestRO")
                .antMatchers("/GetCountryForTestCase").hasRole("TestRO")
                .antMatchers("/GetPropertiesForTestCase").hasRole("TestRO")
                .antMatchers("/GetReport").hasRole("TestRO")
                .antMatchers("/GetStepInLibrary").hasRole("TestRO")
                .antMatchers("/ReadTestCase").hasRole("TestRO")
                .antMatchers("/ReadTestCaseV2").hasRole("TestRO")
                .antMatchers("/ReadTest").hasRole("TestRO")
                .antMatchers("/ReadTestCaseStep").hasRole("TestRO")
                .antMatchers("/GetReportTest").hasRole("TestRO")
                .antMatchers("/ReadTestCaseExecutionByTag").hasRole("TestRO")
                .antMatchers("/ReadExecutionStat").hasRole("TestRO")
                .antMatchers("/ReadQueueStat").hasRole("TestRO")
                .antMatchers("/ReadTagStat").hasRole("TestRO")
                /**
                 * Test
                 */
                .antMatchers("/SqlLibrary.jsp").hasRole("Test")
                .antMatchers("/TestDataLibList.jsp").hasRole("Test")
                .antMatchers("/DuplicateTestCase").hasRole("Test")
                .antMatchers("/UpdateTestCase").hasRole("Test")
                .antMatchers("/UpdateTestCaseMass").hasRole("Test")
                .antMatchers("/CreateTestCaseCountry").hasRole("Test")
                .antMatchers("/DeleteTestCaseCountry").hasRole("Test")
                .antMatchers("/CalculatePropertyForTestCase").hasRole("Test")
                .antMatchers("/UpdateProperties").hasRole("Test")
                .antMatchers("/CreateTestCase").hasRole("Test")
                .antMatchers("/CreateTestCaseLabel").hasRole("Test")
                .antMatchers("/DeleteTestCaseLabel").hasRole("Test")
                .antMatchers("/ImportSeleniumIDE").hasRole("Test")
                .antMatchers("/ImportTestCaseStep").hasRole("Test")
                .antMatchers("/ImportPropertyOfATestCaseToAnOtherTestCase").hasRole("Test")
                .antMatchers("/CreateNotDefinedProperty").hasRole("Test")
                .antMatchers("/DeleteTestData").hasRole("Test")
                .antMatchers("/UpdateTestData").hasRole("Test")
                .antMatchers("/FindAllTestData").hasRole("Test")
                .antMatchers("/ReadTestDataLib").hasRole("Test")
                .antMatchers("/ReadTestDataLibData").hasRole("Test")
                .antMatchers("/ReadSqlLibrary").hasRole("Test")
                .antMatchers("/PictureConnector").hasRole("Test")
                .antMatchers("/UseTestCaseStep").hasRole("Test")
                .antMatchers("/UpdateTestCaseWithDependencies").hasRole("Test")
                .antMatchers("/UpdateTestCaseProperties").hasRole("Test")
                .antMatchers("/Thumbnailer").hasRole("Test")
                .antMatchers("/UpdateTestCaseField").hasRole("Test")
                .antMatchers("/SaveTestCaseLABEL").hasRole("Test")
                .antMatchers("/ReadTestCaseLABEL").hasRole("Test")
                /**
                 * Label
                 */
                .antMatchers("/Label.jsp").hasRole("Label")
                .antMatchers("/CreateLabel").hasRole("Label")
                .antMatchers("/UpdateLabel").hasRole("Label")
                .antMatchers("/DeleteLabel").hasRole("Label")
                /**
                 * TestStepLibrary
                 */
                .antMatchers("/ZZZ").hasRole("TestStepLibrary")
                /**
                 * TestAdmin
                 */
                .antMatchers("/AddTEST").hasRole("TestAdmin")
                .antMatchers("/CreateTest").hasRole("TestAdmin")
                .antMatchers("/DeleteTest").hasRole("TestAdmin")
                .antMatchers("/UpdateTest").hasRole("TestAdmin")
                .antMatchers("/DeleteTestCase").hasRole("TestAdmin")
                .antMatchers("/DeleteTestCaseFromTestPage").hasRole("TestAdmin")
                .antMatchers("/CreateSqlLibrary").hasRole("TestAdmin")
                .antMatchers("/DeleteSqlLibrary").hasRole("TestAdmin")
                .antMatchers("/UpdateSqlLibrary").hasRole("TestAdmin")
                /**
                 * RunTest
                 */
                .antMatchers("/RunTests.jsp").hasRole("RunTest")
                .antMatchers("/findEnvironmentByCriteria").hasRole("RunTest")
                .antMatchers("/UpdateTestCaseExecution").hasRole("RunTest")
                .antMatchers("/RunExecutionInQueue").hasRole("RunTest")
                .antMatchers("/SetTagToExecution").hasRole("RunTest")
                .antMatchers("/GetExecutionQueue").hasRole("RunTest")
                .antMatchers("/UpdateTestCaseExecutionQueue").hasRole("RunTest")
                .antMatchers("/ReadTestCaseExecutionQueue").hasRole("RunTest")
                .antMatchers("/CreateTestCaseExecutionQueue").hasRole("RunTest")
                .antMatchers("/CreateUpdateTestCaseExecutionFile").hasRole("RunTest")
                .antMatchers("/DeleteTestCaseExecutionFile").hasRole("RunTest")
                .antMatchers("/ReadCampaign").hasRole("RunTest")
                .antMatchers("/ReadCampaignParameter").hasRole("RunTest")
                .antMatchers("/GetCampaign").hasRole("RunTest")
                .antMatchers("/UpdateCampaign").hasRole("RunTest")
                .antMatchers("/CreateCampaign").hasRole("RunTest")
                .antMatchers("/DeleteCampaign").hasRole("RunTest")
                .antMatchers("/CreateScheduleEntry").hasRole("RunTest")
                .antMatchers("/ReadScheduleEntry").hasRole("RunTest")
                .antMatchers("/UpdateScheduleEntry").hasRole("RunTest")
                .antMatchers("/DeleteScheduleEntry").hasRole("RunTest")
                /**
                 * TestDataManager
                 */
                .antMatchers("/CreateTestDataLib").hasRole("TestDataManager")
                .antMatchers("/DuplicateTestDataLib").hasRole("TestDataManager")
                .antMatchers("/ImportTestDataLib").hasRole("TestDataManager")
                .antMatchers("/DeleteTestDataLib").hasRole("TestDataManager")
                .antMatchers("/UpdateTestDataLibData").hasRole("TestDataManager")
                .antMatchers("/UpdateTestDataLib").hasRole("TestDataManager")
                .antMatchers("/BulkRenameDataLib").hasRole("TestDataManager")
                /**
                 * IntegratorRO
                 */
                .antMatchers("/AppServiceList.jsp").hasRole("IntegratorRO")
                .antMatchers("/ApplicationObjectList.jsp").hasRole("IntegratorRO")
                .antMatchers("/BuildContent.jsp").hasRole("IntegratorRO")
                .antMatchers("/BuildRevDefinition.jsp").hasRole("IntegratorRO")
                .antMatchers("/Environment.jsp").hasRole("IntegratorRO")
                .antMatchers("/IntegrationStatus.jsp").hasRole("IntegratorRO")
                .antMatchers("/Project.jsp").hasRole("IntegratorRO")
                .antMatchers("/DeployType.jsp").hasRole("IntegratorRO")
                .antMatchers("/BatchInvariant.jsp").hasRole("IntegratorRO")
                .antMatchers("/GetShortTests").hasRole("IntegratorRO")
                .antMatchers("/GetInvariantsForTest").hasRole("IntegratorRO")
                .antMatchers("/GetEnvironmentAvailable").hasRole("IntegratorRO")
                .antMatchers("/FindBuildContent").hasRole("IntegratorRO")
                .antMatchers("/FindCountryEnvironmentDatabase").hasRole("IntegratorRO")
                .antMatchers("/GetCountryEnvParamList").hasRole("IntegratorRO")
                .antMatchers("/GetCountryEnvironmentParameterList").hasRole("IntegratorRO")
                .antMatchers("/FindEnvironments").hasRole("IntegratorRO")
                .antMatchers("/ReadDeployType").hasRole("IntegratorRO")
                .antMatchers("/GetNotification").hasRole("IntegratorRO")
                .antMatchers("/ReadBuildRevisionParameters").hasRole("IntegratorRO")
                .antMatchers("/ReadCountryEnvParam_log").hasRole("IntegratorRO")
                .antMatchers("/ReadBuildRevisionBatch").hasRole("IntegratorRO")
                .antMatchers("/ReadBatchInvariant").hasRole("IntegratorRO")
                .antMatchers("/ReadCountryEnvDeployType").hasRole("IntegratorRO")
                .antMatchers("/ReadCountryEnvironmentDatabase").hasRole("IntegratorRO")
                .antMatchers("/ReadCountryEnvironmentParameters").hasRole("IntegratorRO")
                .antMatchers("/ReadCountryEnvLink").hasRole("IntegratorRO")
                /**
                 * Integrator
                 */
                .antMatchers("/CreateApplication").hasRole("Integrator")
                .antMatchers("/UpdateApplication").hasRole("Integrator")
                .antMatchers("/CreateApplicationObject").hasRole("Integrator")
                .antMatchers("/UpdateApplicationObject").hasRole("Integrator")
                .antMatchers("/DeleteApplicationObject").hasRole("Integrator")
                .antMatchers("/UpdateCountryEnv").hasRole("Integrator")
                .antMatchers("/CreateProject").hasRole("Integrator")
                .antMatchers("/DeleteProject").hasRole("Integrator")
                .antMatchers("/UpdateProject").hasRole("Integrator")
                .antMatchers("/CreateBuildRevisionInvariant").hasRole("Integrator")
                .antMatchers("/UpdateBuildRevisionInvariant").hasRole("Integrator")
                .antMatchers("/DeleteBuildRevisionInvariant").hasRole("Integrator")
                .antMatchers("/CreateRobot").hasRole("Integrator")
                .antMatchers("/UpdateRobot").hasRole("Integrator")
                .antMatchers("/DeleteRobot").hasRole("Integrator")
                .antMatchers("/CreateCountryEnvParam").hasRole("Integrator")
                .antMatchers("/UpdateCountryEnvParam").hasRole("Integrator")
                .antMatchers("/DeleteCountryEnvParam").hasRole("Integrator")
                .antMatchers("/CreateCountryEnvironmentParameter").hasRole("Integrator")
                .antMatchers("/UpdateCountryEnvironmentParameter").hasRole("Integrator")
                .antMatchers("/DeleteCountryEnvironmentParameter").hasRole("Integrator")
                .antMatchers("/CreateCountryEnvironmentDatabase").hasRole("Integrator")
                .antMatchers("/UpdateCountryEnvironmentDatabase").hasRole("Integrator")
                .antMatchers("/DeleteCountryEnvironmentDatabase").hasRole("Integrator")
                .antMatchers("/CreateDeployType").hasRole("Integrator")
                .antMatchers("/UpdateDeployType").hasRole("Integrator")
                .antMatchers("/DeleteDeployType").hasRole("Integrator")
                .antMatchers("/CreateBuildRevisionParameters").hasRole("Integrator")
                .antMatchers("/UpdateBuildRevisionParameters").hasRole("Integrator")
                .antMatchers("/DeleteBuildRevisionParameters").hasRole("Integrator")
                .antMatchers("/CreateBatchInvariant").hasRole("Integrator")
                .antMatchers("/DeleteBatchInvariant").hasRole("Integrator")
                .antMatchers("/UpdateBatchInvariant").hasRole("Integrator")
                .antMatchers("/CreateAppService").hasRole("Integrator")
                .antMatchers("/DeleteAppService").hasRole("Integrator")
                .antMatchers("/UpdateAppService").hasRole("Integrator")
                /**
                 * IntegratorNewChain
                 */
                .antMatchers("/NewChain").hasRole("IntegratorNewChain")
                /**
                 * IntegratorDeploy
                 */
                .antMatchers("/DisableEnvironment").hasRole("IntegratorDeploy")
                .antMatchers("/NewBuildRev").hasRole("IntegratorDeploy")
                .antMatchers("/JenkinsDeploy").hasRole("IntegratorDeploy")
                /**
                 * Administrator
                 */
                .antMatchers("/LogEvent.jsp").hasRole("Administrator")
                .antMatchers("/ParameterList.jsp").hasRole("Administrator")
                .antMatchers("/UserManager.jsp").hasRole("Administrator")
                .antMatchers("/InvariantList.jsp").hasRole("Administrator")
                .antMatchers("/CerberusInformation.jsp").hasRole("Administrator")
                .antMatchers("/ReadUser").hasRole("Administrator")
                .antMatchers("/GetParameter").hasRole("Administrator")
                .antMatchers("/UpdateParameter").hasRole("Administrator")
                .antMatchers("/GetUsers").hasRole("Administrator")
                .antMatchers("/CreateUser").hasRole("Administrator")
                .antMatchers("/UpdateUser").hasRole("Administrator")
                .antMatchers("/DeleteUser").hasRole("Administrator")
                .antMatchers("/ReadLogEvent").hasRole("Administrator")
                .antMatchers("/CreateInvariant").hasRole("Administrator")
                .antMatchers("/UpdateInvariant").hasRole("Administrator")
                .antMatchers("/DeleteInvariant").hasRole("Administrator")
                .antMatchers("/DeleteApplication").hasRole("Administrator")
                .antMatchers("/ReadCerberusDetailInformation").hasRole("Administrator")
                .antMatchers("/ChangeUserPasswordAdmin").hasRole("Administrator")
                .antMatchers("/js/**").permitAll()
                .antMatchers("/css/**").permitAll()
                .antMatchers("/images/**").permitAll()
                .antMatchers("/include/**").permitAll()
                .antMatchers("/dependencies/**").permitAll()
                .antMatchers("/Login*").permitAll()
                /**
                 * ANY
                 */
                .antMatchers("/Homepage.jsp").authenticated()
                .antMatchers("/RobotList.jsp").authenticated()
                .antMatchers("/Homepage").authenticated()
                .antMatchers("/ReadMyUser").authenticated()
                .antMatchers("/ReadExecutionTagHistory").authenticated()
                .antMatchers("/GetInvariantList").authenticated()
                .antMatchers("/ReadCerberusInformation").authenticated()
                .antMatchers("/GeneratePerformanceString").authenticated()
                .antMatchers("/UpdateMyUser").authenticated()
                .antMatchers("/UpdateMyUserSystem").authenticated()
                .antMatchers("/UpdateMyUserReporting").authenticated()
                .antMatchers("/UpdateMyUserReporting1").authenticated()
                .antMatchers("/UpdateMyUserRobotPreference").authenticated()
                .antMatchers("/ReadUserPublic").authenticated()
                .antMatchers("/FindInvariantByID").authenticated()
                .antMatchers("/ImportTestCaseFromJson").authenticated()
                .antMatchers("/GetReportData").authenticated()
                .antMatchers("/ReadApplication").authenticated()
                .antMatchers("/ReadApplicationObject").authenticated()
                .antMatchers("/ReadBuildRevisionInvariant").authenticated()
                .antMatchers("/ReadProject").authenticated()
                .antMatchers("/ReadRobot").authenticated()
                .antMatchers("/ReadCountryEnvParam").authenticated()
                .antMatchers("/GetTestBySystem").authenticated()
                .antMatchers("/GetTestCaseForTest").authenticated()
                .antMatchers("/GetEnvironmentsPerBuildRevision").authenticated()
                .antMatchers("/GetEnvironmentsLastChangePerCountry").authenticated()
                .antMatchers("/ReadAppService").authenticated()
                .antMatchers("/ReadInvariant").authenticated()
                .antMatchers("/ReadTestCaseExecution").authenticated()
                .antMatchers("/ReadTag").authenticated()
                .antMatchers("/ReadParameter").authenticated()
                .antMatchers("/GetExecutionsInQueue").authenticated()
                .antMatchers("/ReadDocumentation").authenticated()
                .antMatchers("/ReadLabel").authenticated();

        if (!isSecurePublicApi) {
            http.authorizeRequests()
                    .antMatchers("/DatabaseMaintenance.jsp").permitAll()
                    .antMatchers("/Documentation.jsp").permitAll()
                    .antMatchers("/Login.jsp").permitAll()
                    .antMatchers("/Logout.jsp").permitAll()
                    .antMatchers("/Error.jsp").permitAll()
                    .antMatchers("/index1.jsp").permitAll()
                    .antMatchers("/index2.jsp").permitAll()
                    .antMatchers("/index3.jsp").permitAll()
                    .antMatchers("/index4.jsp").permitAll()
                    .antMatchers("/ChangePassword.jsp").permitAll()
                    .antMatchers("/RunTestCase").permitAll()
                    .antMatchers("/RunTestCaseV001").permitAll()
                    .antMatchers("/GetNumberOfExecutions").permitAll()
                    .antMatchers("/ResultCI").permitAll()
                    .antMatchers("/ResultCIV001").permitAll()
                    .antMatchers("/ResultCIV002").permitAll()
                    .antMatchers("/ResultCIV003").permitAll()
                    .antMatchers("/ResultCIV004").permitAll()
                    .antMatchers("/NewRelease").hasAnyRole("ANONYMOUS, USER")
                    .antMatchers("/AddToExecutionQueue").permitAll()
                    .antMatchers("/AddToExecutionQueueV001").permitAll()
                    .antMatchers("/AddToExecutionQueueV002").permitAll()
                    .antMatchers("/AddToExecutionQueueV003").permitAll()
                    .antMatchers("/NewBuildRevisionV000").permitAll()
                    .antMatchers("/DisableEnvironmentV000").permitAll()
                    .antMatchers("/NewEnvironmentEventV000").permitAll()
                    .antMatchers("/GetTagExecutions").permitAll()
                    .antMatchers("/GetTESTCasesV000").permitAll()
                    .antMatchers("/manageV001").permitAll()
                    .antMatchers("/ForgotPassword").permitAll()
                    .antMatchers("/ForgotPasswordEmailConfirmation").permitAll()
                    .antMatchers("/ChangeUserPassword").permitAll()
                    .antMatchers("/ReadApplicationObjectImage").permitAll()
                    .antMatchers("/DummyRESTCall").permitAll()
                    .antMatchers("/ReadMyUser").authenticated()
                    .antMatchers("/DummyRESTCallEmpty").permitAll();

        } else {
            http.authorizeRequests()
                    .antMatchers("/DatabaseMaintenance.jsp").hasRole("Administrator")
                    .antMatchers("/Documentation.jsp").hasRole("Administrator")
                    .antMatchers("/Login.jsp").hasRole("Administrator")
                    .antMatchers("/Logout.jsp").hasRole("Administrator")
                    .antMatchers("/Error.jsp").hasRole("Administrator")
                    .antMatchers("/index1.jsp").hasRole("Administrator")
                    .antMatchers("/index2.jsp").hasRole("Administrator")
                    .antMatchers("/index3.jsp").hasRole("Administrator")
                    .antMatchers("/index4.jsp").hasRole("Administrator")
                    .antMatchers("/ChangePassword.jsp").hasRole("Administrator")
                    .antMatchers("/RunTestCase").hasRole("Administrator")
                    .antMatchers("/RunTestCaseV001").hasRole("Administrator")
                    .antMatchers("/GetNumberOfExecutions").hasRole("Administrator")
                    .antMatchers("/ResultCI").hasRole("Administrator")
                    .antMatchers("/ResultCIV001").hasRole("Administrator")
                    .antMatchers("/ResultCIV002").hasRole("Administrator")
                    .antMatchers("/ResultCIV003").hasRole("Administrator")
                    .antMatchers("/ResultCIV004").hasRole("Administrator")
                    .antMatchers("/NewRelease").hasRole("Administrator")
                    .antMatchers("/AddToExecutionQueue").hasRole("Administrator")
                    .antMatchers("/AddToExecutionQueueV001").hasRole("Administrator")
                    .antMatchers("/AddToExecutionQueueV002").hasRole("Administrator")
                    .antMatchers("/AddToExecutionQueueV003").hasRole("Administrator")
                    .antMatchers("/NewBuildRevisionV000").hasRole("Administrator")
                    .antMatchers("/DisableEnvironmentV000").hasRole("Administrator")
                    .antMatchers("/NewEnvironmentEventV000").hasRole("Administrator")
                    .antMatchers("/GetTagExecutions").hasRole("Administrator")
                    .antMatchers("/GetTESTCasesV000").hasRole("Administrator")
                    .antMatchers("/manageV001").hasRole("Administrator")
                    .antMatchers("/ForgotPassword").hasRole("Administrator")
                    .antMatchers("/ForgotPasswordEmailConfirmation").hasRole("Administrator")
                    .antMatchers("/ChangeUserPassword").hasRole("Administrator")
                    .antMatchers("/ReadApplicationObjectImage").hasRole("Administrator")
                    .antMatchers("/DummyRESTCall").hasRole("Administrator")
                    .antMatchers("/DummyRESTCallEmpty").hasRole("Administrator");

        }

        //http.authorizeRequests().anyRequest().authenticated();
          if (!isKeycloak) {
                http.formLogin()
                .loginPage("/Login.jsp")
                //.loginPage("http://localhost:8180/auth/realms/SpringBootKeycloak/protocol/openid-connect/auth?client_id=login-app")
                .loginProcessingUrl("/login")
                .defaultSuccessUrl("/Homepage.jsp", false)
                .failureUrl("/Login.jsp?error=1")
                //.failureHandler(authenticationFailureHandler())
                .and()
                .logout()
                .logoutUrl("/perform_logout")
                .deleteCookies("JSESSIONID");
                //.logoutSuccessHandler(logoutSuccessHandler());

        }
        if (isKeycloak) {
            http.formLogin();
                //.loginPage("http://localhost:8180/auth/realms/R-qa/protocol/openid-connect/auth?client_id=Cerberus-SpringBoot")
                //.oauth2ResourceServer()
                //.jwt()
               // .jwtAuthenticationConverter(grantedAuthoritiesExtractor());
        } else {
            http.csrf().disable();
        }

    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth)
            throws Exception {

        if (!isKeycloak) {
            PasswordEncoder encoder = new MessageDigestPasswordEncoder("SHA-1");
            String query = "SELECT login as username, password, true as enabled FROM user WHERE login = ? ";
            String query2 = "select login as username, concat('ROLE_', groupname) as role from usergroup where login = ?";

            auth.jdbcAuthentication()
                    .dataSource(dataSource)
                    .usersByUsernameQuery(query)
                    .authoritiesByUsernameQuery(query2)
                    .passwordEncoder(encoder);

        }

    }

    @Bean
    Converter<Jwt, AbstractAuthenticationToken> grantedAuthoritiesExtractor() {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(myCustomJwtGrantedAuthoritiesExtractor);
        return jwtAuthenticationConverter;
    }

    @Bean
    JwtDecoder jwtDecoderByJwkKeySetUri() {
        NimbusJwtDecoder nimbusJwtDecoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
        if (issuerUri != null) {
            nimbusJwtDecoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(issuerUri));
        }
        return nimbusJwtDecoder;
    }

}
