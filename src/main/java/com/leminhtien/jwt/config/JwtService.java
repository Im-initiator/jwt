package com.leminhtien.jwt.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    @Value("${application.security.jwt.secret-key}")
    private  String SECRET_KEY;

    @Value("${application.security.jwt.expiration}")
    private long jwtExpiration;

    @Value("${application.security.jwt.refresh-token.expiration}")
    private long refreshJwtExpiration;

    //Tạo khóa
    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);//chuyển khóa thành một mảng bytes
        return Keys.hmacShaKeyFor(keyBytes);//tạo và tả về một khóa dạng SHA dùng để tạo chữ ký và xác minh JWT
        //Key là một lớp cung cấp các method tạo quá và chữ ký.
    }

    //vẫn là tạo token
    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(),userDetails);//HasMap chứa thông tin muốn cho vào jwt có thể là role(list) hoặc hơn nữa.
    }

    public String generateRefreshToken(UserDetails userDetails){
        return generateRefreshToken(new HashMap<>(),userDetails);//HasMap chứa thông tin muốn cho vào jwt có thể là role(list) hoặc hơn nữa.
    }

    //Tạo token
    public String generateToken(
            Map<String,Object> extractClaims,
            UserDetails userDetails
    ){
        return buildToken(extractClaims,userDetails,jwtExpiration);

    }

    public String generateRefreshToken(
            Map<String,Object> extractClaims,
            UserDetails userDetails
    ){
        return buildToken(extractClaims,userDetails,refreshJwtExpiration);

    }

    private String buildToken(Map<String,Object> extractClaims,
                              UserDetails userDetails,
                              long expiration)
    {
        return
                Jwts
                        .builder()
                        .setClaims(extractClaims)
                        .setSubject(userDetails.getUsername()) //thiết lập subject là userName
                        .setIssuedAt(new Date(System.currentTimeMillis())) //thiết lập ngày tạo
                        .setExpiration(new Date(System.currentTimeMillis()+expiration)) //thiết lập ngày hết hạn
                        .signWith(getSignInKey(), SignatureAlgorithm.HS256) //thiết lập khóa
                        .compact();
    }



    //Lấy ra userName từ token
    public String extractUserName(String token){
        return extractClaim(token,Claims::getSubject);
    }

    //thực hiện chức năng phân tích jwt và trả về kết quả mong muốn với tham số là đối tượng Claim và function
    public <T> T extractClaim(String token, Function<Claims, T> claimResolver){
        final Claims claims = extractAllClaims(token);
        return claimResolver.apply(claims);//thực hiện hàm chức năng claimResolver với đối số claims và trả về kết quả T

    }

    //Phân tích JWT và trả về đối tượng Claims chứa thông tin trong phần payload của JWT
    private Claims extractAllClaims(String token){
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public boolean isTokenValid(String token,UserDetails userDetails){
        final String userName = extractUserName(token);
        return (userDetails.getUsername().equals(userName)&& !isTokenExpired(token));
    }

    //Kiểm tra token đã hết hạn chưa
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    //Lấy ra ngày hết hạn
    private Date extractExpiration(String token) {
        return extractClaim(token,Claims::getExpiration);
    }


}

