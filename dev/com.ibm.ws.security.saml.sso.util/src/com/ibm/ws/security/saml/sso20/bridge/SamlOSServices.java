/*******************************************************************************
 * Copyright (c) 2025 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 *
 * Contributors:
 *     IBM Corporation - initial API and implementation
 *******************************************************************************/
package com.ibm.ws.security.saml.sso20.bridge;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.opensaml.saml.saml2.binding.decoding.impl.HTTPPostDecoder;
import org.osgi.framework.ServiceReference;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Component;

import com.ibm.websphere.ras.Tr;
import com.ibm.websphere.ras.TraceComponent;
import com.ibm.websphere.ras.annotation.Trivial;
import com.ibm.ws.security.SecurityService;
import com.ibm.ws.security.saml.Constants;
import com.ibm.ws.security.saml.SsoConfig;
import com.ibm.ws.security.saml.SsoOSUtil;
import com.ibm.ws.security.saml.SsoSamlService;
import com.ibm.ws.security.saml.TraceConstants;
import com.ibm.ws.security.saml.error.SamlException;
import com.ibm.wsspi.kernel.service.utils.AtomicServiceReference;
import com.ibm.wsspi.kernel.service.utils.ConcurrentServiceReferenceMap;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.primitive.NonnullSupplier;

@Component(service = SsoOSUtil.class, name = "SsoOSUtil", immediate = true, property = "service.vendor=IBM")
public class SamlOSServices implements SsoOSUtil {
    private static TraceComponent tc = Tr.register(SamlOSServices.class,
                                                   TraceConstants.TRACE_GROUP,
                                                   TraceConstants.MESSAGE_BUNDLE);
    public static final String KEY_SECURITY_SERVICE = "securityService";
    public static final String KEY_ID = "id";
    public static final String KEY_SAML_SERVICE = "samlService";
    private final ConcurrentServiceReferenceMap<String, SsoSamlService> samlServiceRef = new ConcurrentServiceReferenceMap<String, SsoSamlService>(KEY_SAML_SERVICE);
    protected final AtomicServiceReference<SecurityService> securityServiceRef = new AtomicServiceReference<SecurityService>(KEY_SECURITY_SERVICE);
    @SuppressWarnings("unused")
    private static final String WWW_AUTHENTICATE_HEADER = "WWW-Authenticate";

    protected void setSecurityService(ServiceReference<SecurityService> reference) {
        securityServiceRef.setReference(reference);
    }

    protected void unsetSecurityService(ServiceReference<SecurityService> reference) {
        securityServiceRef.unsetReference(reference);
    }

    @Trivial
    protected void setSamlService(ServiceReference<SsoSamlService> ref) {
        synchronized (samlServiceRef) {
            samlServiceRef.putReference((String) ref.getProperty(KEY_ID), ref);
        }
    }

    @Trivial
    protected void unsetSamlService(ServiceReference<SsoSamlService> ref) {
        synchronized (samlServiceRef) {
            samlServiceRef.removeReference((String) ref.getProperty(KEY_ID), ref);
        }
    }

    protected void activate(ComponentContext cc) {
        securityServiceRef.activate(cc);
        samlServiceRef.activate(cc);
        Tr.info(tc, "SAML20_ENDPOINT_SERVICE_ACTIVATED");
    }

    protected void deactivate(ComponentContext cc) {
        securityServiceRef.deactivate(cc);
        samlServiceRef.deactivate(cc);
    }

    /*
     * protected void handleSamlOSRequest(HttpServletRequest request,
     * HttpServletResponse response) throws SamlException {
     * SsoRequest samlRequest = (SsoRequest) request.getAttribute(Constants.ATTRIBUTE_SAML20_REQUEST);
     * if (samlRequest != null) {
     * handleSamlOSRequest(request, response, samlRequest);
     * }
     * }
     */

    /**
     * @param request
     * @param response
     * @param servletContext
     * @param samlRequest
     * @throws SamlException
     */
    protected void handleSamlOSRequest(HttpServletRequest request, HttpServletResponse response, String sp) throws SamlException {
        SsoSamlService samlService = getSsoSamlService(response, sp);
        if (samlService != null) {
            SsoConfig ssoConfig = samlService.getConfig();
            if (ssoConfig != null) {
                String reqUrl = request.getRequestURL().toString();
                if (!checkHttpsRequirement(ssoConfig, reqUrl)) {
                    throw new SamlException("SAML20_EP_PROTOCOL_NOT_HTTPS", null, new Object[] { reqUrl });
                } /*
                   * else {
                   * Map<String, Object> parameters = getParameterMap(samlService);
                   * //SsoHandler samlHandler = HandlerFactory.getHandlerInstance(samlRequest); //AcsHandler
                   * //samlHandler.handleRequest(request, response, samlRequest, parameters);
                   * }
                   */
                else {

                }
            }
        }
    }

    @Override
    public HTTPPostDecoder getSamlHttpPostDecoder(String acsUrl, String sp, Object req) {
        HTTPPostDecoder decoder = new SamlOSHTTPPostDecoder(acsUrl);
        decoder.setHttpServletRequestSupplier(new ExampleSupplier<HttpServletRequest>((jakarta.servlet.http.HttpServletRequest) req)); //v5 update
        //decoder.setHttpServletRequestSupplier(req); //v5 update
        decoder.setParserPool(XMLObjectProviderRegistrySupport.getParserPool());
        try {
            decoder.initialize();
        } catch (ComponentInitializationException e) {
            // TODO Auto-generated catch block
            // Do you need FFDC here? Remember FFDC instrumentation and @FFDCIgnore
            //e.printStackTrace();
        }
        return decoder;
    }

    boolean checkHttpsRequirement(SsoConfig ssoConfig, String urlStr) {
        boolean metHttpsRequirement = true;
        if (ssoConfig.isHttpsRequired()) {
            if (urlStr != null && !urlStr.startsWith("https")) {
                metHttpsRequirement = false;
            }
        }
        return metHttpsRequirement;
    }

    /**
     * @param samlRequest
     * @param samlService
     * @return
     */
    private Map<String, Object> getParameterMap(SsoSamlService samlService) {
        HashMap<String, Object> results = new HashMap<String, Object>();
        results.put(Constants.KEY_SAML_SERVICE, samlService);
        results.put(Constants.KEY_SECURITY_SERVICE, securityServiceRef.getService());
        return results;
    }

    private SsoSamlService getSsoSamlService(HttpServletResponse response, String sp) throws SamlException {
        SsoSamlService service = samlServiceRef.getService(sp);
        if (service == null || !service.isEnabled()) { // if no ssoService or the ssoService is disabled
            service = null; // even it has an service, as long as it is disable. It is the same as null
            throw new SamlException("SAML20_NO_SUCH_ACS_PROVIDER", null, new Object[] { sp });
        } /*
           * else {
           * samlRequest.setSsoSamlService(service); // for error handling
           * }
           */
        return service;
    }

    public final class ExampleSupplier<T> implements NonnullSupplier<HttpServletRequest> {
        private final jakarta.servlet.http.HttpServletRequest theValue;

        public ExampleSupplier(final HttpServletRequest value) {
            theValue = value;
        }

        @Override
        public HttpServletRequest get() {
            return theValue;
        }

    }

    /** Message decoder implementing the SAML 2.0 HTTP POST binding. */
    public final class SamlOSHTTPPostDecoder extends HTTPPostDecoder {

        String acsUrl;

        public SamlOSHTTPPostDecoder(String acsUrl) {
            this.acsUrl = acsUrl;
        }

        //@Override
        protected String getActualReceiverEndpointURI(@SuppressWarnings("rawtypes") MessageContext messageContext) throws MessageDecodingException {
            return acsUrl;
        }

        @Override
        protected InputStream getBase64DecodedMessage(HttpServletRequest request) throws MessageDecodingException {
            InputStream inputStream = super.getBase64DecodedMessage(request); //v5 update
            if (tc.isDebugEnabled()) {
                if (inputStream instanceof ByteArrayInputStream) {
                    ByteArrayInputStream byteStream = (ByteArrayInputStream) inputStream;
                    int iAvailable = byteStream.available();
                    if (iAvailable > 0) {
                        byte[] bytes = new byte[iAvailable];
                        byteStream.read(bytes, 0, iAvailable);
                        byteStream.reset();
                        Tr.debug(tc, "decoded saml response:" + new String(bytes, StandardCharsets.UTF_8));
                    } else {
                        Tr.debug(tc, "decoded saml response has bytes count:" + iAvailable);
                    }
                }
            }
            return inputStream;
        }
    }
}
