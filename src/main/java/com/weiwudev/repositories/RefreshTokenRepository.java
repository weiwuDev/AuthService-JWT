package com.weiwudev.repositories;

import com.weiwudev.models.RefreshToken;
import org.springframework.data.mongodb.repository.ReactiveMongoRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RefreshTokenRepository extends ReactiveMongoRepository<RefreshToken, String> {
}
