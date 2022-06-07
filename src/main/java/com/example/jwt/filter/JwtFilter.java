package com.example.jwt.filter;

import com.example.jwt.auth.ApplicationUserService;
import com.example.jwt.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtFilter extends OncePerRequestFilter {

    private JwtUtil jwtUtil;
    private ApplicationUserService applicationUserService;

    @Autowired
    public JwtFilter(JwtUtil jwtUtil, ApplicationUserService applicationUserService) {
        this.jwtUtil = jwtUtil;
        this.applicationUserService = applicationUserService;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String path = request.getRequestURI();
        // Skip the filter on /user/login/ API call as user will not have the Token at that time
        return "/user/login".equals(path);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // This header will contain the token
        String authorization = request.getHeader("Authorization");
        String token = null;
        String username = null;

        if (null != authorization && authorization.startsWith("Bearer ")) {
            token = authorization.substring(7); // the token string after "Bearer "
            username = jwtUtil.getUsernameFromToken(token);
        }

        // Authenticate the user
        if (null != username && null == SecurityContextHolder.getContext().getAuthentication()) {
            UserDetails userDetails = applicationUserService.loadUserByUsername(username);

            if (jwtUtil.validateToken(token, userDetails)) {

                UsernamePasswordAuthenticationToken authenticationToken =
                        new UsernamePasswordAuthenticationToken(
                                userDetails, null, userDetails.getAuthorities()
                        );

                authenticationToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );

                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
            else {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST);
            }

            filterChain.doFilter(request, response);
        }
        else {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST);
        }
    }
}
