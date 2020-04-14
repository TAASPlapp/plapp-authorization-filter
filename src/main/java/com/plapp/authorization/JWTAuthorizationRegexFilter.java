package com.plapp.authorization;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import sun.misc.IOUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class JWTAuthorizationRegexFilter extends BasicAuthenticationFilter {
    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String TOKEN_PREFIX = "Bearer ";

    private final Logger logger = LoggerFactory.getLogger(JWTAuthorizationRegexFilter.class);

    private ObjectMapper objectMapper = new ObjectMapper();
    private PublicKey publicKey;

    public JWTAuthorizationRegexFilter(AuthenticationManager authenticationManager) throws Exception {
        super(authenticationManager);
        readPublicKey();
    }

    public void readPublicKey() throws Exception {
        //String url = "https://github.com/TAASPlapp/plapp-authorization-filter/blob/master/src/main/resources/public.der?raw=true";
        //logger.info("Loading public key file from " + url);
        //InputStream inputStream = new URL(url).openStream();

        InputStream inputStream = new ClassPathResource("private.der").getInputStream();
        logger.info("Loading private key from classpath, available bytes: " + inputStream.available());
        byte[] keyBytes = new byte[inputStream.available()];
        inputStream.read(keyBytes);

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        publicKey = keyFactory.generatePublic(keySpec);
        logger.info("Public key loaded");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String header = request.getHeader(AUTHORIZATION_HEADER);
        if (header != null && header.startsWith(TOKEN_PREFIX)) {
            logger.info("Found authorization header");
            Authentication authentication = validateJwtAndAuthorizeRequest(request, response);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } else {
            logger.info("Authorization header not found");
        }

        filterChain.doFilter(request, response);
    }

    private Authentication validateJwtAndAuthorizeRequest(HttpServletRequest request,
                                                          HttpServletResponse response) throws IOException {
        String jwt = request.getHeader(AUTHORIZATION_HEADER);
        String uri = request.getRequestURI();
        logger.info("Request uri: " + uri);

        if (jwt == null)
            return null;

        Jws<Claims> jws;

        try {
            jws = Jwts.parser()
                    .setSigningKey(publicKey)
                    .parseClaimsJws(jwt.replace(TOKEN_PREFIX, ""));
        } catch (JwtException e) {
            logger.error("Invalid token: " + e.getMessage());
            return null;
        }

        Claims claims = jws.getBody();
        Long subject = Long.parseLong(claims.getSubject());
        String authoritiesString = claims.get("authorities", String.class);

        List<ResourceAuthority> authorities = objectMapper.readValue(
                authoritiesString,
                new TypeReference<List<ResourceAuthority>>() {});

        boolean requestAuthorized = false;
        Iterator<ResourceAuthority> iterator = authorities.iterator();
        while(iterator.hasNext() && !requestAuthorized) {
            ResourceAuthority authority = iterator.next();

            logger.info("Found authority: " + authority.getAuthority());
            logger.info("Values in authority: " + authority.getValues());

            Pattern pattern = Pattern.compile(authority.getAuthority());
            Matcher matcher = pattern.matcher(uri);

            if (matcher.matches()) {
                logger.info("Uri matches authority regex");
                logger.info("Got match: " + matcher.group(1));
                Long matchedValue = Long.parseLong(matcher.group(1));

                if (!authority.getValues().contains(matchedValue)) {
                    logger.info("Unauthorized");
                    return null;
                } else {
                    requestAuthorized = true;
                }
            }
        }

        return new UsernamePasswordAuthenticationToken(subject, null, authorities);
    }
}

