package io.pivotal.ntlm.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestOperations;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.net.URI;

import static io.pivotal.ntlm.filter.Headers.DOMAIN_HEADER;
import static io.pivotal.ntlm.filter.Headers.USER_HEADER;


@RestController
final class Controller {

    private static final String FORWARDED_URL = "X-CF-Forwarded-Url";
    private static final String PROXY_METADATA = "X-CF-Proxy-Metadata";
    private static final String PROXY_SIGNATURE = "X-CF-Proxy-Signature";

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    private final RestOperations restOperations;

    @Autowired
    Controller(RestOperations restOperations) {
        this.restOperations = restOperations;
    }

    @RequestMapping(headers = {FORWARDED_URL, PROXY_METADATA, PROXY_SIGNATURE})
    ResponseEntity<?> service(RequestEntity<byte[]> incoming, HttpServletRequest request) throws IOException {
        this.logger.info("Incoming Request: {}", incoming);


        RequestEntity<?> outgoing = getOutgoingRequest(incoming, request.getHeader( USER_HEADER ), request.getHeader( DOMAIN_HEADER ));

        this.logger.info("Outgoing Request: {}", outgoing);

        ResponseEntity<byte[]> responseEntity = this.restOperations.exchange(outgoing, byte[].class);
        return responseEntity;
    }

    private static RequestEntity<?> getOutgoingRequest(RequestEntity<?> incoming, String user, String domain) {
        HttpHeaders headers = new HttpHeaders();
        headers.putAll(incoming.getHeaders());
        headers.add( USER_HEADER, user );
        headers.add( DOMAIN_HEADER, domain );

        URI uri = headers.remove(FORWARDED_URL).stream()
                .findFirst()
                .map(URI::create)
                .orElseThrow(() -> new IllegalStateException(String.format("No %s header present", FORWARDED_URL)));

        System.out.println( uri.getQuery() );

        return new RequestEntity<>(incoming.getBody(), headers, incoming.getMethod(), uri);
    }
}
