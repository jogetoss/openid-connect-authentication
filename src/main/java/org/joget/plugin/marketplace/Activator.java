package org.joget.plugin.marketplace;

import java.util.ArrayList;
import java.util.Collection;
import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceRegistration;

public class Activator implements BundleActivator {

    public static final String VERSION = "7.0.9";

    protected Collection<ServiceRegistration> registrationList;

    public void start(BundleContext context) {
        registrationList = new ArrayList<ServiceRegistration>();

        //Register plugin here
        registrationList.add(context.registerService(OpenIDDirectoryManager.class.getName(), new OpenIDDirectoryManager(), null));
        registrationList.add(context.registerService(ExtUserSecurityImpl.class.getName(), new ExtUserSecurityImpl(), null));
        registrationList.add(context.registerService(OpenIDHashVariable.class.getName(), new OpenIDHashVariable(), null));
    }

    public void stop(BundleContext context) {
        for (ServiceRegistration registration : registrationList) {
            registration.unregister();
        }
    }
}