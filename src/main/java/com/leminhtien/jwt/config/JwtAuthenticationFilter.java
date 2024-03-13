package com.leminhtien.jwt.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsServices;


    /*filter này chỉ áp dụng với những request có token ở header. Nếu token hợp lệ sẽ tự động
    * Login bằng cách tìm một user ở CSDL có email trùng khớp sau đó tự động login với user được lấy lên*/
    @Override
    protected void doFilterInternal(
         @NonNull HttpServletRequest request,
         @NonNull   HttpServletResponse response,
         @NonNull   FilterChain filterChain
    ) throws ServletException, IOException {
        final  String authHeader = request.getHeader("Authorization");
        final  String jwt;
        final  String userEmail;
        if (authHeader == null || !authHeader.startsWith("Bearer ")){
            filterChain.doFilter(request,response);
            return;
        }
        //tách header token
        jwt = authHeader.substring(7);
        userEmail = jwtService.extractUserName(jwt);
        //Nếu lấy được email từ token và chưa đăng nhập thì  xác thực email
        if (userEmail!=null && SecurityContextHolder.getContext().getAuthentication() == null){
            UserDetails userDetails = this.userDetailsServices.loadUserByUsername(userEmail);
            //Kiểm tra nếu email hợp lệ thì tự động login
            if (jwtService.isTokenValid(jwt,userDetails)){
                //login
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                //thiết lập trạng thái trình duyệt
                authenticationToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );
                //Thiết lập UsernamePasswordAuthenticationToken vào SecurityContext = đăng nhập
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
        }
        filterChain.doFilter(request,response);
    }
}
