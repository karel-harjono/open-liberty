/*******************************************************************************
 * Copyright (c) 2025 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 *******************************************************************************/
package com.ibm.ws.security.saml.sso20.binding;

import java.util.Map;

import org.opensaml.saml.saml2.binding.decoding.impl.HTTPPostDecoder;
import org.osgi.framework.ServiceReference;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.osgi.service.component.annotations.ReferencePolicyOption;

import com.ibm.websphere.ras.Tr;
import com.ibm.websphere.ras.TraceComponent;
import com.ibm.ws.security.saml.SsoOSUtil;
import com.ibm.wsspi.kernel.service.utils.AtomicServiceReference;

/**
 *
 */
@Component(service = SsoOSUtilHelper.class, name = "SsoOSUtilHelper", immediate = true, property = "service.vendor=IBM")
public class SsoOSUtilHelper {

    private static final TraceComponent tc = Tr.register(SsoOSUtilHelper.class, TraceConstants.TRACE_GROUP, TraceConstants.MESSAGE_BUNDLE);

    public static final String SAML_SSO_OS_UTIL = "SsoOSUtil";
    protected final AtomicServiceReference<SsoOSUtil> ssoOSUtilRef = new AtomicServiceReference<SsoOSUtil>(SAML_SSO_OS_UTIL);

    @Reference(service = SsoOSUtil.class, name = SAML_SSO_OS_UTIL, cardinality = ReferenceCardinality.OPTIONAL, policy = ReferencePolicy.DYNAMIC,
               policyOption = ReferencePolicyOption.GREEDY)
    protected void setJwtSSOToken(ServiceReference<SsoOSUtil> ref) {
        ssoOSUtilRef.setReference(ref);
    }

    protected void unsetJwtSSOToken(ServiceReference<SsoOSUtil> ref) {
        ssoOSUtilRef.unsetReference(ref);
    }

    @org.osgi.service.component.annotations.Activate
    protected void activate(ComponentContext cc) {
        ssoOSUtilRef.activate(cc);
        if (tc.isDebugEnabled()) {
            Tr.debug(tc, "SAML SSO OS helper service is activated");
        }
        if (tc.isDebugEnabled()) {
            Tr.debug(tc, "SAML SSO OS helper helper service is activated");
        }
    }

    @org.osgi.service.component.annotations.Modified
    protected void modified(Map<String, Object> props) {
    }

    @org.osgi.service.component.annotations.Deactivate
    protected void deactivate(ComponentContext cc) {
        ssoOSUtilRef.deactivate(cc);
        if (tc.isDebugEnabled()) {
            Tr.debug(tc, "SAML SSO OS helper helper service is deactivated");
        }
        if (tc.isDebugEnabled()) {
            Tr.debug(tc, "SAML SSO OS helper service is activated");
        }
    }

    public HTTPPostDecoder getSamlHttpPostDecoder(String acs, String sp, Object servletRequest) {
        if (ssoOSUtilRef.getService() != null) {
            return ssoOSUtilRef.getService().getSamlHttpPostDecoder(acs, sp, servletRequest);
        }
        return null;
    }

}
