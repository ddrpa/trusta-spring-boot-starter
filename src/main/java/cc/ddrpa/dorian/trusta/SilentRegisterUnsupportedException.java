package cc.ddrpa.dorian.trusta;

/**
 * Thrown when a {@link SubjectStrategy} does not support silent registration
 * and no local user was found for the JWT subject.
 */
public class SilentRegisterUnsupportedException extends RuntimeException {

    public SilentRegisterUnsupportedException(String issuer) {
        super("Silent registration is not supported for issuer: " + issuer);
    }

    public SilentRegisterUnsupportedException() {
        super("Silent registration is not supported");
    }
}
