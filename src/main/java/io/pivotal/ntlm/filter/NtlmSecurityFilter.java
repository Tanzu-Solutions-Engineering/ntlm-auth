/* Copyright (c) 2018, IOPLEX Software
 *
 * All source, binaries and materials in this package are protected by the
 * EULA in the LICENSE.txt file in the top level directory of this package
 * unless explicitly stated otherwise within individual source files. The
 * following license applies to this source file only.
 *
 * Copyright (c) 2018, IOPLEX Software
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *   * Neither the name of IOPLEX Software nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL COPYRIGHT OWNER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */
package io.pivotal.ntlm.filter;

import io.pivotal.ntlm.filter.AddParamsToHeader;
import jespa.http.HttpSecurityService;
import jespa.http.HttpSecurityServletRequest;
import jespa.ntlm.NtlmSecurityProvider;
import jespa.security.Account;
import jespa.security.SecurityProvider;
import jespa.security.SecurityProviderException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

/* This example illustrates:
 *
 *  1. How to extend the HttpSecurityService directly. Note that the
 *  HttpSecurityService does not implement Filter so, unlike this example,
 *  you do not have to create a filter (although because doFilter uses
 *  FilterChain you would need to create a dummy FilterChain class).
 *
 *  2. How to redirect logging to log4j [1].
 *
 *  3. How to protect the service.password by encrypting it so that it
 *  does not appear as plaintext in the configuration.
 *
 *  4. How to bypass the filter. This example just uses a my.disabled
 *  property which is a boolean that indicates whether or not the
 *  filter should be disabled.
 *
 *  5. How to use an inner class as a "dummy" FilterChain to perform work after
 *  the request has passed through the HttpSecurityService (as opposed to
 *  using a separate Filter later in the chain). This can be used to retreieve
 *  the SecurityProvider and Account associated with the authentication. See
 *  InnerFilterChain below.
 *
 * [1] IMPORTANT: Make sure that you record all Jespa log entries to a
 * separate file. If you request help from IOPLEX Support they will request
 * a jespa.log.level = 4 log file obtained as described in the Obtaining
 * a Complete Jespa Log File section of Appendix A of the Jespa Operator's
 * Manual.
 */
@Component
public class NtlmSecurityFilter extends HttpSecurityService implements Filter
{
    @Value("${vcap.services.jespa-service.credentials.jespa.log.level}") String _logLevel;
    @Value("${vcap.services.jespa-service.credentials.jespa.service.acctname}") String _acctName;
    @Value("${vcap.services.jespa-service.credentials.jespa.service.password}") String _password;
    @Value("${vcap.services.jespa-service.credentials.jespa.bindstr}") String _bindStr;
    @Value("${vcap.services.jespa-service.credentials.jespa.account.canonicalForm}")String _canonicalForm;
    @Value("${vcap.services.jespa-service.credentials.jespa.dns.servers}") String _dnsServers;
    @Value("${vcap.services.jespa-service.credentials.jespa.dns.site}") String _dnsSite;

    private Map props = null;

    public void init(FilterConfig config) throws ServletException
    {
        Map<String,String> properties = new HashMap<>();

        /* Just copy the Filter init-params and copy them into a properties
         * Map for HttpSecurityService.init.
         */

        Enumeration<String> e = config.getInitParameterNames();
        while (e.hasMoreElements()) {
            String name = e.nextElement();
            properties.put(name, config.getInitParameter(name));
        }

        properties.put( "jespa.log.level", _logLevel );
        properties.put( "jespa.service.acctname", _acctName );
        properties.put( "jespa.service.password", _password );
        properties.put( "jespa.bindstr", _bindStr );
        properties.put( "jespa.account.canonicalForm", _canonicalForm );
        properties.put( "jespa.dns.servers", _dnsServers );
        properties.put( "jespa.dns.site", _dnsSite );

        try {
            super.init(config.getFilterName(), config.getServletContext(), properties);
        } catch (SecurityProviderException spe) {
            throw new ServletException(spe);
        }
    }

    public void destroy()
    {
        /* It is important to call super.destroy() here to ensure that the log
         * file descriptor is closed when the webapp is reloaded without restarting
         * the JVM.
         */
        super.destroy();
    }

    /* This static inner class is a "dummy" FilterChain that demonstrates how
     * a custom filter can perform work *after* it has been successfully
     * processed by the HttpSecurityService. This allows you to get to the
     * SecurityProvider used to authenticate the user, the Account object and
     * associated data (without using a separate Filter in the chain).
     *
     * Note that this is called for each and every request regardless of whether
     * or not authentication has just occured so if you want to perform work
     * only once per session, store something in the session that includes
     * the authenticated user's identity (getRemoteUser) and check that identity
     * to see if it changes. If it has not changed, you may choose to skip said
     * work.
     */
    class InnerFilterChain implements FilterChain
    {

        FilterChain inner;

        InnerFilterChain(FilterChain inner)
        {
            this.inner = inner;
        }

        public void doFilter(ServletRequest request,
                             ServletResponse response) throws IOException, ServletException
        {
            System.out.println("MyHttpSecurityFilter: The request has successfully passed through the HttpSecurityService");
            String user = "XX";
            String domain = "XX";

            if (request instanceof HttpSecurityServletRequest) {

                System.out.println("MyHttpSecurityFilter: The request has been authenticated (or the connection was previously authenticated) by the HttpSecurityService");

                HttpSecurityServletRequest hssr = (HttpSecurityServletRequest)request;
                SecurityProvider sp = hssr.getSecurityProvider();
                if (sp instanceof NtlmSecurityProvider) {

                    System.out.println("MyHttpSecurityFilter: The request has been authenticated (or the connection was previously authenticated) using the NtlmSecurityProvider");

                    NtlmSecurityProvider nsp = (NtlmSecurityProvider)sp;
                    try {
                        Account acct = nsp.getAccount(null, null);

                        ///// check to see if you want to do work here /////
                        user = hssr.getRemoteUser();
                        domain = (String)acct.getProperty( "domain.dns.name" );

                        /* See jespa.ntlm.NtlmSecurityProvider.getAccount() API documentation for
                         * complete list of proeperties in an Account returned by an authenticated NSP
                         */
                        System.out.println("MyHttpSecurityFilter: getRemoteUser: " + hssr.getRemoteUser() + ", domain.dns.name=" + acct.getProperty("domain.dns.name") + ", sAMAccountName=" + acct.getProperty("sAMAccountName"));

                    } catch (SecurityProviderException spe) {
                        throw new ServletException(spe);
                    }
                }
            }

            /* Now that we have done our work, now call doFilter on the origial FilterChain.
             */
            inner.doFilter(new AddParamsToHeader((HttpServletRequest) request, user, domain), response);
        }
    }

    /* This demonstrates how to save an authentication exception message in the
     * HttpSession. Presumably the message will be retrieved and removed from the
     * session in the subsequent request (the redirect to the fallback.location
     * page). See the HttpSecurityProvider.onException API documentation for details.
     */
    protected void onException(SecurityProviderException spe,
                               HttpServletRequest req,
                               HttpServletResponse rsp,
                               SecurityProvider sp)
    {
        System.err.println("MyHttpSecurityService: onException: " + spe);

        HttpSession ssn = req.getSession(true);
        ssn.setAttribute("my.message", spe.getMessage());
    }

    public void doFilter(ServletRequest request,
                         ServletResponse response,
                         FilterChain chain) throws IOException, ServletException
    {
        /* This illustrates how to disable the HttpSecurityService
         * entirely. This might be useful if, for example, you wanted another
         * filter in the chain to assume responsibility of securing your application.
         *
         * The condition used to determine if the HttpSecurityService should be
         * invoked could be anything including a regex of the requested object,
         * a database query, etc (although one should make sure it is not something
         * that can be supplied by the client as that would be a security
         * vulnerbility).
         *
         * Note that with this particular implementation where my.disabled is read
         * from the properties.path file, if it is disabled it cannot be un-disabled
         * without reloading the webapp because super.doFilter is what ultimately
         * checks and reads the properties file. Meaning if we do
         * not call super.doFilter(), the properties file will not be checked and
         * of course onPropertiesUpdate will not be called and my.disabled will
         * forever remain true.
         */
        String disabled = (String)props.get("my.disabled");
        boolean isDisabled = disabled != null &&
                (disabled.equalsIgnoreCase("true") ||
                        disabled.equals("1") ||
                        disabled.equalsIgnoreCase("yes"));

        if (isDisabled) {

            System.out.println("MyHttpSecurityFilter: my.disabled = true, calling chain.doFilter directly");

            chain.doFilter(new AddParamsToHeader((HttpServletRequest) request, "corby", "page"), response);
        } else {
            super.doFilter(request, response, new InnerFilterChain(chain));
        }
    }

    protected void onPropertiesUpdate(Map props) throws SecurityProviderException
    {
        this.props = props;

        super.onPropertiesUpdate(props);

        System.out.println("MyHttpSecurityService: properties updated: " + props);
    }
}
