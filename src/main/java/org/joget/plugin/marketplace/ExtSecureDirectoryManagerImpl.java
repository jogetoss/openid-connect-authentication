package org.joget.plugin.marketplace;

import java.util.HashMap;
import java.util.Map;
import org.joget.apps.app.service.AppUtil;
import org.joget.directory.model.service.UserSecurity;
import org.joget.directory.model.service.UserSecurityFactory;
import org.joget.plugin.directory.SecureDirectoryManagerImpl;
import org.joget.plugin.directory.dao.UserExtraDao;
import org.joget.plugin.directory.dao.UserPasswordHistoryDao;

public class ExtSecureDirectoryManagerImpl extends SecureDirectoryManagerImpl implements UserSecurityFactory {

    private UserSecurity userSecurity;

    public ExtSecureDirectoryManagerImpl(Map properties) {
        super(properties);
    }

    /**
     * Override this method to return a custom UserSecurity object to customize the login form footer
     * @return 
     */
    @Override
    public UserSecurity getUserSecurity() {
        if (userSecurity == null) {
            userSecurity = new ExtUserSecurityImpl();
            UserExtraDao userExtraDao = (UserExtraDao)AppUtil.getApplicationContext().getBean("userExtraDao");
            UserPasswordHistoryDao userPasswordHistoryDao = (UserPasswordHistoryDao)AppUtil.getApplicationContext().getBean("userPasswordHistoryDao");
            ((ExtUserSecurityImpl)userSecurity).setUserExtraDao(userExtraDao);
            ((ExtUserSecurityImpl)userSecurity).setUserPasswordHistoryDao(userPasswordHistoryDao);
        }
        Map<String, Object> usProperties = new HashMap<String, Object>();
        Map<String, Object> properties = getProperties();
        if (properties != null) {
            usProperties.putAll(properties);
        }
        userSecurity.setProperties(usProperties);
        return userSecurity;
    }
    
}

