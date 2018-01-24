package org.abstractj.kalium.crypto;

import static org.abstractj.kalium.NaCl.Sodium.CRYPTO_PWHASH_ALG_DEFAULT;
import static org.abstractj.kalium.NaCl.Sodium.CRYPTO_PWHASH_STRBYTES;
import static org.abstractj.kalium.NaCl.sodium;

import org.abstractj.kalium.encoders.Encoder;

public class Argon2 {
    Argon2() {
    }

    public String hash(byte[] passwd, byte[] salt, long opslimit, long memlimit) {
        byte[] buffer = new byte[CRYPTO_PWHASH_STRBYTES];
        sodium().crypto_pwhash(buffer, CRYPTO_PWHASH_STRBYTES, passwd, passwd.length, salt, opslimit, memlimit, 1);
        return buffer.toString();
    }

    public String hashid(byte[] passwd, byte[] salt, long opslimit, long memlimit, long parallelism) {
        byte[] buffer = new byte[CRYPTO_PWHASH_STRBYTES];
        sodium().argon2id_hash_raw(opslimit, memlimit, parallelism, passwd, passwd.length, salt, salt.length, buffer, buffer.length);
        return buffer.toString();
    }

    public String hash(byte[] passwd, Encoder encoder, long opslimit, long memlimit) {
        byte[] buffer = new byte[CRYPTO_PWHASH_STRBYTES];
        sodium().crypto_pwhash_str_alg(buffer, passwd, passwd.length, opslimit, memlimit, CRYPTO_PWHASH_ALG_DEFAULT);
        return encoder.encode(buffer);
    }

    public boolean verify(byte[] hashed_passwd, byte[] passwd) {
        int result = sodium().crypto_pwhash_str_verify(hashed_passwd, passwd, passwd.length);
        return result == 0;
    }

//    int
//    crypto_pwhash_str_alg(char out[crypto_pwhash_STRBYTES],
//                      const char * const passwd, unsigned long long passwdlen,
//                          unsigned long long opslimit, size_t memlimit, int alg)
//    {
//        switch (alg) {
//            case crypto_pwhash_ALG_ARGON2I13:
//                return crypto_pwhash_argon2i_str(out, passwd, passwdlen,
//                        opslimit, memlimit);
//            case crypto_pwhash_ALG_ARGON2ID13:
//                return crypto_pwhash_argon2id_str(out, passwd, passwdlen,
//                        opslimit, memlimit);
//        }
//        sodium_misuse();
//    /* NOTREACHED */
//    }
}
