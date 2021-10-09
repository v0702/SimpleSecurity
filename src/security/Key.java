package security;

public class Key {
    private final byte[] key;
    private final byte[] salt;

    public Key(byte[] key, byte[] salt) {
        this.key = key;
        this.salt = salt;
    }

    public byte[] getKey() {
        return key;
    }

    public byte[] getSalt() {
        return salt;
    }
}
