package io.pivotal.ntlm.filter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

import static io.pivotal.ntlm.filter.Headers.DOMAIN_HEADER;
import static io.pivotal.ntlm.filter.Headers.USER_HEADER;

public class AddParamsToHeader extends HttpServletRequestWrapper {
    private String _user;
    private String _domain;

    public AddParamsToHeader(HttpServletRequest request, String user, String domain) {
        super(request);
        _user = user;
        _domain = domain;
    }

    public String getHeader(String name) {
        String header = super.getHeader(name);

        String result;
        switch (name) {
            case USER_HEADER:
                result = _user;
                break;
            case DOMAIN_HEADER:
                result = _domain;
                break;
            default:
                result = (header != null) ? header : super.getParameter(name);
                break;
        }

        return result;
    }

    public Enumeration<String> getHeaderNames() {
        List<String> names = Collections.list(super.getHeaderNames());
        names.addAll(Collections.list(super.getParameterNames()));
        names.add( USER_HEADER );
        names.add( DOMAIN_HEADER );
        return Collections.enumeration(names);
    }
}
