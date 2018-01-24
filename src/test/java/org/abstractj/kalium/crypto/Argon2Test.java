package org.abstractj.kalium.crypto;

import org.abstractj.kalium.NaCl;
import org.abstractj.kalium.encoders.Encoder;
import org.junit.Test;

import static org.abstractj.kalium.NaCl.sodium;
import static org.abstractj.kalium.fixture.TestVectors.PWHASH_MESSAGE;

public class Argon2Test {
    private final Argon2 argon2 = new Argon2();

    @Test
    public void testPWHash() {
        String result = argon2.hash(
                "password".getBytes(),
                Encoder.RAW,
                2, //NaCl.Sodium.CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
                65536*1024);
        System.out.println(result);
//        assertEquals("Hash is invalid", )is

    }

    @Test
    public void testPWHashID() {

        sodium().sodium_init();
        String result = argon2.hashid(
                "password".getBytes(),
                new Random().randomBytes(NaCl.Sodium.CRYPTO_PWHASH_ARGON2ID_SALTBYTES),
                2, //NaCl.Sodium.CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
                65536*1024,
                4
        );
        System.out.println(result);
//        assertEquals("Hash is invalid", )is

    }
}
