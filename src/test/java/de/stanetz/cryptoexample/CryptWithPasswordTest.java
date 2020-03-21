package de.stanetz.cryptoexample;

import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CryptWithPasswordTest {

    private static CryptWithPassword testee;

    static {
        final long start = System.currentTimeMillis();
        testee = new CryptWithPassword(new SecureRandom(), 32);
        System.out.println("Init " + (System.currentTimeMillis() - start));
    }


    @Test
    void createRoundtrip() throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, InvalidAlgorithmParameterException, BadPaddingException, NoSuchPaddingException {
        final String password = "Test";
        final String text = "äöüßqwe€dahfla fa lfha fh ajdfh ajhf ahf ajhf lhdslahfsajlhfalh adjhf ahf lahlfhasdl";
        System.out.println("Start " + new Date());
        final byte[] encrypt = testee.encrypt(text, password.toCharArray());
        System.out.println("Encrypted " + new Date());
        final String decrypt = testee.decrypt(encrypt, password.toCharArray());
        System.out.println("Final " + new Date());
        assertEquals(text, decrypt);
    }

}