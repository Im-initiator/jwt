package com.leminhtien.jwt.token;

import com.leminhtien.jwt.user.User;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.stereotype.Component;

@Entity
@Table
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Token {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column
    private String token;

    @Enumerated(EnumType.STRING)
    @Column
    private TokenType tokenType;

    @Column
    private boolean expired;

    @Column
    private boolean revoked;

    @ManyToOne
    @JoinColumn(name = "user_id")
    private User user;

}
