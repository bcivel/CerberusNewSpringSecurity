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
package org.cerberus.servlet.crud.usermanagement;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import static org.cerberus.config.SecurityConfiguration.AUTHENTICATION_VALUE_KEYCLOAK;
import org.cerberus.crud.entity.Invariant;
import org.cerberus.crud.entity.UserGroup;
import org.cerberus.crud.entity.User;
import org.cerberus.crud.entity.UserSystem;
import org.cerberus.crud.factory.IFactoryUser;
import org.cerberus.crud.service.*;
import org.cerberus.crud.service.impl.LogEventService;
import org.cerberus.exception.CerberusException;
import org.cerberus.crud.service.impl.UserGroupService;
import org.cerberus.crud.service.impl.UserService;
import org.cerberus.util.StringUtil;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;

/**
 *
 * @author bcivel
 */
@WebServlet(name = "ReadMyUser", urlPatterns = {"/ReadMyUser"})
public class ReadMyUser extends HttpServlet {
    
    private static boolean isKeycloak;
    @Value("${cerberus.authentication}")
    public void setAuthentication(String value) {
        this.isKeycloak = AUTHENTICATION_VALUE_KEYCLOAK.equals(value);
    }
    
    private static String authentication;
    @Value("${cerberus.authentication}")
    public void setAuthenticationMode(String value) {
        this.authentication = value;
    }
    
    private static String keycloakRealm;
    @Value("${keycloak.realm}")
    public void setKeycloakRealm(String value) {
        this.keycloakRealm = value;
    }
    
    private static String keycloakUrl;
    @Value("${keycloak.url}")
    public void setKeycloakUrl(String value) {
        this.keycloakUrl = value;
    }
    

    private IInvariantService invariantService;
    private IUserService userService;
    private IFactoryUser userFactory;
    private IUserSystemService userSystemService;
    private IUserGroupService userGroupService;
    private ILogEventService logEventService;
    private IParameterService parameterService;

    private static final Logger LOG = LogManager.getLogger(ReadMyUser.class);

    /**
     * Processes requests for both HTTP <code>GET</code> and <code>POST</code>
     * methods.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    protected void processRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        ApplicationContext appContext = WebApplicationContextUtils.getWebApplicationContext(this.getServletContext());
        userService = appContext.getBean(UserService.class);
        userFactory = appContext.getBean(IFactoryUser.class);
        invariantService = appContext.getBean(IInvariantService.class);
        userSystemService = appContext.getBean(IUserSystemService.class);
        userGroupService = appContext.getBean(UserGroupService.class);
        logEventService = appContext.getBean(ILogEventService.class);
        parameterService = appContext.getBean(IParameterService.class);

        //boolean isDeploymentOn = parameterService.getParameterBooleanByKey("cerberus_deploymentmode_isdeploymentmodeenabled", "", false);
        //LOG.debug("========================================");
        //LOG.debug("IS ON DEPLOYMENT : " + isDeploymentOn);
        response.setContentType("application/json");
        response.setCharacterEncoding("utf8");

        JSONObject data = new JSONObject();

        try {

            String user = request.getUserPrincipal().getName();
            LOG.debug("Getting user data for (request.getUserPrincipal().getName()) : " + user);

            // In case we activated KeyCloak, we create the user on the fly in order to allow to administer the system list.
            String authMode = "";
            if (authentication != null) {
                authMode = authentication;
                LOG.debug("Authentification JAVA parameter " + authentication + " for keycloak value : '" + authMode + "'");
                if (authMode.equals(AUTHENTICATION_VALUE_KEYCLOAK)) {
                    if (!userService.isUserExist(user)) {
                        User myUser = userFactory.create(0, user, "NOAUTH", "N", "", "", "", "en", "", "", "", "", "", "", "", "", "", "");
                        LOG.debug("Create User.");
                        userService.insertUserNoAuth(myUser);
                        userSystemService.createSystemAutomatic(user);
                        logEventService.createForPrivateCalls("/ReadMyUser", "CREATE", "Create User automaticaly: ['" + user + "']", request);

                    }
                }
            }
            User myUser = userService.findUserByKey(user);
            data.put("login", myUser.getLogin());
            data.put("name", myUser.getName());
            data.put("team", myUser.getTeam());
            data.put("defaultSystem", myUser.getDefaultSystem());
            data.put("request", myUser.getRequest());
            data.put("email", myUser.getEmail());
            data.put("language", myUser.getLanguage());
            data.put("robotHost", myUser.getRobotHost());
            data.put("robotPort", myUser.getRobotPort());
            data.put("robotPlatform", myUser.getRobotPort());
            data.put("robotBrowser", myUser.getRobotPort());
            data.put("robotVersion", myUser.getRobotPort());
            data.put("robot", myUser.getRobot());
            data.put("reportingFavorite", myUser.getReportingFavorite());
            data.put("userPreferences", myUser.getUserPreferences());
            data.put("isKeycloak", isKeycloak);
            //data.put("isDeploymentMode", parameterService.getParameterBooleanByKey("cerberus_deploymentmode_isdeploymentmodeenabled", "", false));

            // Define submenu entries
            JSONObject menu = new JSONObject();
            if (isKeycloak) {
                // Name displayed in menu
                menu.put("nameDisplay", user);

                String keyCloakUrl = StringUtil.addSuffixIfNotAlready(keycloakUrl, "/");

                menu.put("accountLink", keyCloakUrl + "realms/" + keycloakRealm + "/account/");
                menu.put("logoutLink", keyCloakUrl + "realms/" + keycloakRealm + "/protocol/openid-connect/logout?redirect_uri=%LOGOUTURL%");
            } else {
                // Name displayed in menu
                menu.put("nameDisplay", myUser.getLogin());
                menu.put("accountLink", "");
                menu.put("logoutLink", "./Logout.jsp");
            }
            data.put("menu", menu);

            JSONArray groups = new JSONArray();
            if (isKeycloak) {
                List<String> groupList = new ArrayList<>();
                groupList.add("Label");
                groupList.add("RunTest");
                groupList.add("Test");
                groupList.add("TestAdmin");
                groupList.add("TestDataManager");
                groupList.add("TestRO");
                groupList.add("TestStepLibrary");
                groupList.add("IntegratorNewChain");
                groupList.add("Integrator");
                groupList.add("IntegratorDeploy");
                groupList.add("IntegratorRO");
                groupList.add("Administrator");
                for (String myGroup : groupList) {
                    if (request.isUserInRole("ROLE_"+myGroup)) {
                        groups.put(myGroup);
                    }
                }
            } else {
                for (UserGroup group : userGroupService.findGroupByKey(myUser.getLogin())) {
                    groups.put(group.getGroup());
                }
            }
            data.put("group", groups);

            JSONArray systems = new JSONArray();
            List<UserSystem> userSysList = userSystemService.findUserSystemByUser(myUser.getLogin());
            if (request.isUserInRole("Administrator")) {
                // If user is Administrator, he has access to all groups.
                List<Invariant> invList = invariantService.readByIdName("SYSTEM");
                for (Invariant invariant : invList) {
                    systems.put(invariant.getValue());
                }
            } else {
                for (UserSystem sys : userSysList) {
                    systems.put(sys.getSystem());
                }
            }
            data.put("system", systems);

            HttpSession session = request.getSession();
            session.setAttribute("MySystem", myUser.getDefaultSystem());
            session.setAttribute("MySystemsAllow", userSysList);
            session.setAttribute("MySystemsIsAdministrator", (request.isUserInRole("Administrator")));
            session.setAttribute("MyLang", myUser.getLanguage());

        } catch (CerberusException ex) {
            LOG.error(ex.toString(), ex);
            response.getWriter().print(ex.getMessageError().getDescription());
        } catch (JSONException ex) {
            LOG.error(ex.toString(), ex);
        } catch (NullPointerException ex) {
            LOG.error(ex.toString(), ex);
            response.sendRedirect("./Login.jsp");
        }
        response.getWriter().print(data.toString());

    }

    // <editor-fold defaultstate="collapsed" desc="HttpServlet methods. Click on the + sign on the left to edit the code.">
    /**
     * Handles the HTTP <code>GET</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    /**
     * Handles the HTTP <code>POST</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    /**
     * Returns a short description of the servlet.
     *
     * @return a String containing servlet description
     */
    @Override
    public String getServletInfo() {
        return "Short description";
    }// </editor-fold>

}
