package com.example.signingalorithms

import android.util.Base64
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.ArgumentMatchers
import org.mockito.ArgumentMatchers.anyInt
import org.mockito.ArgumentMatchers.anyString
import org.mockito.Mockito.`when`
import org.mockito.Mockito.verify
import org.powermock.api.mockito.PowerMockito
import org.powermock.core.classloader.annotations.PrepareForTest
import org.powermock.modules.junit4.PowerMockRunner
import java.security.spec.InvalidKeySpecException

@RunWith(PowerMockRunner::class)
@PrepareForTest(Base64::class)
class SigningAlgorithmsTest {

    private companion object {
        val PRIVATE_KEY_PEM = """-----BEGIN PRIVATE KEY-----
        MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQggJTXnmiG+VNXkdPr
        ILylN+a6Gcia8Tf2JIRfOQOxGeqhRANCAARgY4WvJLgfONJUIjNzOxAdm/GjRCDZ
        j4e8WV9m5Tr+8/qT+jqaMfBivIwCABcfPP8K3p31GyCT0l8Be/O/m6ZO
        -----END PRIVATE KEY-----""".trimIndent()
        val PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYGOFryS4HzjSVCIzczsQHZvxo0Qg
        2Y+HvFlfZuU6/vP6k/o6mjHwYryMAgAXHzz/Ct6d9Rsgk9JfAXvzv5umTg==
        -----END PUBLIC KEY-----""".trimIndent()
        const val TEST_STRING = "test"
    }

    @Before
    fun setUp() {
        PowerMockito.mockStatic(Base64::class.java)
        `when`(
            Base64.encode(
                ArgumentMatchers.any(),
                anyInt()
            )
        ).thenAnswer { invocation ->
            java.util.Base64.getEncoder()
                .encode(invocation.arguments[0] as ByteArray)
        }
        `when`(
            Base64.decode(
                anyString(),
                anyInt()
            )
        ).thenAnswer { invocation ->
            java.util.Base64.getMimeDecoder()
                .decode(invocation.arguments[0] as String)
        }
    }

    @Test
    fun `given a private key PEM file, when signing the file, then the signature validation will return true`() {
        val privateKey = initializePrivateKey(PRIVATE_KEY_PEM)
        val publicKey = initializePublicKey(PUBLIC_KEY_PEM)
        val dataToSign = TEST_STRING.toByteArray(Charsets.UTF_8)
        val signature = signDocument(privateKey, dataToSign)
        assert(verifySignature(publicKey, dataToSign, signature))
    }

    @Test
    fun `given a private key PEM file, when signing the file, then the signature validation will fail`() {
        val privateKey = initializePrivateKey(PRIVATE_KEY_PEM)
        val publicKeyPEM = """-----BEGIN PUBLIC KEY-----
           MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYGOFryS4HzjSVCIzczsQHZvxo0Qg
           2Y+HvFlfZuU6/vP6k/o6mjHwYryMAgAXHzz/Ct6d9Rsgk9JfAXvzv5umTG==
           -----END PUBLIC KEY-----""".trimIndent()
        val publicKey = initializePublicKey(publicKeyPEM)
        val dataToSign = TEST_STRING.toByteArray(Charsets.UTF_8)
        val signature = signDocument(privateKey, dataToSign)
        Assert.assertFalse(verifySignature(publicKey, dataToSign, signature))
    }

    @Test(expected = InvalidKeySpecException::class)
    fun `given a private key PEM file, when signing the file, then the signature validation will return InvalidKeySpecException`() {
        val privateKeyPEM = """-----BEGIN PRIVATE KEY-----
        MIGkAgEBBDD2MFRv6BpJU6/zDI2yBfVbe0oeU1nFAoYMedDGtcdwHyWNJSeiYRBA
        pVNzMxPSBLWgBwYFK4EEACKhZANiAAQBttEp/qUGnDlmL+o6KZnVs+RoBnEBEGho
        PxSUu1Xfj77QQqfuqHOCRzWXseQA1aZB/h6VQEiFovugtG1G3HaMxxrqLLxb10g2
        BMaRcAfZyeqc3O0Ui8XXb1esn0gOrCu=
        -----END PRIVATE KEY-----""".trimIndent()
        val privateKey = initializePrivateKey(privateKeyPEM)
        val publicKey = initializePublicKey(PUBLIC_KEY_PEM)
        val dataToSign = TEST_STRING.toByteArray(Charsets.UTF_8)
        val signature = signDocument(privateKey, dataToSign)
        verify(verifySignature(publicKey, dataToSign, signature))
    }

}
