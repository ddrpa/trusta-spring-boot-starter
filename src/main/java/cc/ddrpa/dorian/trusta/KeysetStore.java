package cc.ddrpa.dorian.trusta;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeyStatus;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.TinkJsonProtoKeysetFormat;
import com.google.crypto.tink.jwt.JwtEcdsaParameters;
import com.google.crypto.tink.jwt.JwtPublicKeySign;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.security.GeneralSecurityException;
import java.util.EnumSet;
import java.util.Objects;

/**
 * Owns the local signing keyset: loading it (or generating it on first startup when the file is
 * missing), persisting changes atomically with owner-only permissions, and exposing the signing
 * primitive and the published public keyset.
 * <p>
 * Pure Java — no Spring or servlet dependencies. Key-mutating operations are synchronized; the
 * published state (primitive, public JSON) is published via volatile fields.
 */
class KeysetStore {

    private static final Logger logger = LoggerFactory.getLogger(KeysetStore.class);

    private final Path privateKeysetPath;

    private volatile KeysetHandle privateKeysetHandle;
    private volatile String publicKeySetAsJSONString;
    private volatile JwtPublicKeySign jwtPublicKeySign;

    KeysetStore(Path privateKeysetPath) throws GeneralSecurityException, IOException {
        this.privateKeysetPath = Objects.requireNonNull(privateKeysetPath, "privateKeysetPath");
        handlePrivateKeysetHandle();
    }

    /**
     * The Tink signing primitive over the current primary key (or the whole enabled keyset).
     */
    JwtPublicKeySign getSignPrimitive() {
        return jwtPublicKeySign;
    }

    /**
     * JSON of the public part of the current keyset, as published for remote verification.
     */
    String getPublicKeysetJson() {
        return publicKeySetAsJSONString;
    }

    /**
     * Tink key id of the current primary signing key.
     */
    int getPrimaryKeyId() {
        return privateKeysetHandle.getPrimary().getId();
    }

    /**
     * Adds a new ES256 primary key with a fresh {@code kid}, persists the keyset atomically and
     * refreshes the public keyset. Other enabled keys stay enabled.
     *
     * @return the Tink key id of the new primary signing key
     */
    synchronized int rotateSigningKey() throws GeneralSecurityException, IOException {
        JwtEcdsaParameters parameters = jwtEcdsaParameters();
        KeysetHandle.Builder builder = KeysetHandle.newBuilder(privateKeysetHandle);
        builder.addEntry(KeysetHandle.generateEntryFromParameters(parameters).withRandomId().makePrimary());
        applyKeyset(builder.build());
        int primaryId = privateKeysetHandle.getPrimary().getId();
        logger.info("Rotated signing key, new primary key id={}", primaryId);
        return primaryId;
    }

    /**
     * Disables a non-primary signing key by its Tink key id and persists the change.
     *
     * @param keyId the Tink key id of the key to disable
     * @throws IllegalArgumentException if {@code keyId} is the primary key or unknown
     */
    synchronized void disableSigningKey(int keyId) throws GeneralSecurityException, IOException {
        if (privateKeysetHandle.getPrimary().getId() == keyId) {
            throw new IllegalArgumentException("Cannot disable the primary signing key id=" + keyId);
        }
        KeysetHandle.Builder fresh = KeysetHandle.newBuilder();
        boolean found = false;
        for (int i = 0; i < privateKeysetHandle.size(); i++) {
            KeysetHandle.Entry entry = privateKeysetHandle.getAt(i);
            KeysetHandle.Builder.Entry imported = KeysetHandle.importKey(entry.getKey()).withFixedId(entry.getId());
            if (entry.getId() == keyId) {
                imported.setStatus(KeyStatus.DISABLED);
                found = true;
            } else {
                imported.setStatus(entry.getStatus());
            }
            if (entry.isPrimary()) {
                imported.makePrimary();
            }
            fresh.addEntry(imported);
        }
        if (!found) {
            throw new IllegalArgumentException("Unknown signing key id=" + keyId);
        }
        applyKeyset(fresh.build());
        logger.info("Disabled signing key id={}", keyId);
    }

    /**
     * Disables every enabled non-primary signing key, leaving only the current primary enabled.
     */
    synchronized void disableNonPrimaryKeys() throws GeneralSecurityException, IOException {
        int primaryId = privateKeysetHandle.getPrimary().getId();
        KeysetHandle.Builder fresh = KeysetHandle.newBuilder();
        int disabled = 0;
        for (int i = 0; i < privateKeysetHandle.size(); i++) {
            KeysetHandle.Entry entry = privateKeysetHandle.getAt(i);
            KeysetHandle.Builder.Entry imported = KeysetHandle.importKey(entry.getKey()).withFixedId(entry.getId());
            if (entry.getId() == primaryId) {
                imported.setStatus(KeyStatus.ENABLED).makePrimary();
            } else if (entry.getStatus() == KeyStatus.ENABLED) {
                imported.setStatus(KeyStatus.DISABLED);
                disabled++;
            } else {
                imported.setStatus(entry.getStatus());
            }
            fresh.addEntry(imported);
        }
        applyKeyset(fresh.build());
        logger.info("Disabled {} non-primary signing keys; primary id={}", disabled, primaryId);
    }

    private void handlePrivateKeysetHandle() throws GeneralSecurityException, IOException {
        if (!Files.exists(privateKeysetPath)) {
            // The signing key is always generated on first startup when the file is missing.
            applyKeyset(KeysetHandle.generateNew(jwtEcdsaParameters()));
            logger.warn("Generated a new signing keyset at {} (owner-only). Back it up; consider "
                    + "external key provisioning for production.", privateKeysetPath);
            return;
        }
        applyKeysetInMemory(TinkJsonProtoKeysetFormat.parseKeyset(
                Files.readString(privateKeysetPath), InsecureSecretKeyAccess.get()));
    }

    private void applyKeyset(KeysetHandle handle) throws GeneralSecurityException, IOException {
        // Compute every fallible in-memory value first, then persist atomically, and only then
        // switch the volatile state: a failed write must never leave memory and disk diverged.
        JwtPublicKeySign newSign = handle.getPrimitive(RegistryConfiguration.get(), JwtPublicKeySign.class);
        String newPublicKeySetAsJSONString = TinkJsonProtoKeysetFormat.serializeKeyset(
                handle.getPublicKeysetHandle(), InsecureSecretKeyAccess.get());
        String newPrivateKeysetAsJSONString = TinkJsonProtoKeysetFormat.serializeKeyset(
                handle, InsecureSecretKeyAccess.get());
        writePrivateKeysetAtomically(newPrivateKeysetAsJSONString);
        this.privateKeysetHandle = handle;
        this.jwtPublicKeySign = newSign;
        this.publicKeySetAsJSONString = newPublicKeySetAsJSONString;
    }

    private void applyKeysetInMemory(KeysetHandle handle) throws GeneralSecurityException {
        this.privateKeysetHandle = handle;
        this.jwtPublicKeySign = handle.getPrimitive(RegistryConfiguration.get(), JwtPublicKeySign.class);
        this.publicKeySetAsJSONString = TinkJsonProtoKeysetFormat.serializeKeyset(
                handle.getPublicKeysetHandle(), InsecureSecretKeyAccess.get());
    }

    /**
     * Atomically replace the persisted private keyset (temp file in the same directory + rename),
     * with owner-only permissions. On failure the on-disk keyset is left untouched.
     */
    private void writePrivateKeysetAtomically(String privateKeysetJson) throws IOException {
        Path dir = privateKeysetPath.toAbsolutePath().getParent();
        if (dir == null) {
            dir = Paths.get(".").toAbsolutePath();
        }
        if (!Files.isDirectory(dir)) {
            throw new IOException(
                    "Cannot persist keyset: parent directory does not exist: " + dir);
        }
        Path tmp = Files.createTempFile(dir, privateKeysetPath.getFileName().toString(), ".tmp");
        boolean completed = false;
        try {
            Files.writeString(tmp, privateKeysetJson, StandardCharsets.UTF_8);
            restrictToOwner(tmp);
            try {
                Files.move(tmp, privateKeysetPath,
                        StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(tmp, privateKeysetPath, StandardCopyOption.REPLACE_EXISTING);
            }
            completed = true;
        } finally {
            if (!completed) {
                Files.deleteIfExists(tmp);
            }
        }
    }

    private static void restrictToOwner(Path path) throws IOException {
        if (!path.getFileSystem().supportedFileAttributeViews().contains("posix")) {
            return;
        }
        Files.setPosixFilePermissions(path,
                EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
    }

    private static JwtEcdsaParameters jwtEcdsaParameters() throws GeneralSecurityException {
        return JwtEcdsaParameters.builder()
                .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
                .setKidStrategy(JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                .build();
    }
}
