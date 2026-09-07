package cc.ddrpa.dorian.trusta;

import java.util.Optional;

/**
 * Shallow strategy for matching a JWT {@code sub} to a local user and optionally
 * silently registering when no user exists.
 * <p>
 * Bind an implementation class via {@code trusta.trusted-issuers[].identifier}.
 * Multiple issuers may share the same strategy bean.
 *
 * @param <T> local user type
 */
public interface SubjectStrategy<T> {

    /**
     * Find a local user by the JWT subject (shared identifier).
     *
     * @param subject JWT {@code sub}
     * @param claims  verified token metadata
     * @return local user if present
     */
    Optional<T> find(String subject, VerifiedClaims claims);

    /**
     * Silently register a local user when {@link #find} returns empty.
     * Default implementation rejects silent registration.
     *
     * @param subject JWT {@code sub}
     * @param claims  verified token metadata
     * @return newly created local user
     */
    default T register(String subject, VerifiedClaims claims) {
        throw new SilentRegisterUnsupportedException(claims.getIssuer());
    }
}
