package org.joget.plugin.marketplace;

import java.util.Map;
import org.joget.apps.app.service.AppUtil;
import org.joget.commons.util.ResourceBundleUtil;
import org.joget.directory.model.service.DirectoryManagerProxyImpl;
import org.joget.directory.model.service.UserSecurity;
import org.joget.plugin.base.HiddenPlugin;
import org.joget.plugin.base.PluginManager;
import org.joget.plugin.directory.SecureDirectoryManagerImpl;
import org.joget.plugin.directory.UserSecurityImpl;

public class ExtUserSecurityImpl extends UserSecurityImpl implements HiddenPlugin {

    public ExtUserSecurityImpl() {
        super();
    }
    
    @Override
    public String getName() {
        return "OpenID Connect User Security";
    }

    @Override
    public String getDescription() {
        return "User Security for OpenID Connect";
    }

    @Override
    public String getVersion() {
        return Activator.VERSION;
    }
    
    @Override
    public String getLabel() {
        return "OpenID Connect User Security";
    }

    /**
     * Override login form footer to insert SSO login button
     */
    @Override
    public String getLoginFormFooter() {
        DirectoryManagerProxyImpl dm = (DirectoryManagerProxyImpl) AppUtil.getApplicationContext().getBean("directoryManager");
        SecureDirectoryManagerImpl dmImpl = (SecureDirectoryManagerImpl) dm.getDirectoryManagerImpl();

        // original footer
        String content = "";
        
        if ("true".equals(getPropertyString("enableForgotPassword"))) {
            content += "<a rel=\"popup\" style=\"cursor:pointer;text-decoration:underline;\" onclick=\"forgotPassword();return false;\">"+ResourceBundleUtil.getMessage("app.edm.label.forgotPassword")+"</a>\n";

            String contextPath = AppUtil.getRequestContextPath();
            content += "<script>function forgotPassword(){new PopupDialog('" + contextPath + "/web/json/plugin/"+UserSecurityImpl.class.getName()+"/service?a=fp', ' ').init();}</script>";

            String token = getForgotPasswordToken();
            if (token != null) {
                content += "<script>$(document).ready(function(){new PopupDialog('" + contextPath + "/web/json/plugin/"+UserSecurityImpl.class.getName()+"/service?a=fpcp&t="+token+"', ' ').init();});</script>";
            }
        }

        for (UserSecurity us : getSubUserSecurityImpls()) {
            content += us.getLoginFormFooter();
        }
        String redirectUrl = OpenIDDirectoryManager.getCallbackURL()+"?login=1";
        // append login button
        content += "<style>\n"
                + "#openIDLogin {\n"
                + "    background: " + dmImpl.getPropertyString("buttonBackgroundColor") + ";\n"
                + "    padding: 10px 20px;\n"
                + "    border-radius: 3px;\n"
                + "    text-align: left;\n"
                + "    display: block;\n"
                + "    width: fit-content;\n"
                + "    color: " + dmImpl.getPropertyString("buttonTextColor") + ";\n"
                + "    margin: 20px 100px;\n"
                + "}\n"
                + "#icon {\n"
                + "padding-right: 20px;\n"
                + "}\n"
                + "</style>";
        content += "<a href=\"" + redirectUrl + "\" id=\"openIDLogin\"><i id=\"icon\" class=\"" + dmImpl.getPropertyString("buttonIcon") + "\"></i>" + dmImpl.getPropertyString("buttonText") + "</a>";

        return content;
    }

    /**
     * Override this method so that the templates will be read from the main
     * non-OSGI classloader
     *
     * @param template
     * @param model
     * @return
     */
    @Override
    protected String getTemplate(String template, Map model) {
        PluginManager pluginManager = (PluginManager) AppUtil.getApplicationContext().getBean("pluginManager");
        String content = pluginManager.getPluginFreeMarkerTemplate(model, UserSecurityImpl.class.getName(), "/templates/" + template + ".ftl", null);
        return content;
    }
}
