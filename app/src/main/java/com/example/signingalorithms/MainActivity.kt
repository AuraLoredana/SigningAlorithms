package com.example.signingalorithms

import android.os.Bundle
import android.util.Base64
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import androidx.security.crypto.EncryptedFile
import androidx.security.crypto.EncryptedFile.Builder
import androidx.security.crypto.MasterKeys
import kotlinx.android.synthetic.main.activity_main.*
import java.io.File
import java.io.IOException
import java.util.logging.*

private const val FILE_NAME = "signedLog.log"

class MainActivity : AppCompatActivity() {
    private var fileHandler: FileHandler? = null
    private var file: File? = null
    private val privateKey = initializePrivateKey(PRIVATE_KEY_PEM)
    private val publicKey = initializePublicKey(PUBLIC_KEY_PEM)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val masterKeyAlias = MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC)

        val encryptedFile = generateFileAndWriteLogs()?.let {
            Builder(
                it,
                applicationContext,
                masterKeyAlias,
                EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
            ).build()
        }

        write_logs.setOnClickListener {
            try {
                generateFileAndWriteLogs()?.let {
                    if (it.exists()) it.delete()
                }

            } catch (exception: IOException) {
                Log.d("File:", exception.message.toString())
            }
        }

        write_encrypted_logs.setOnClickListener {
            try {
                generateFileAndWriteLogs()?.let {
                    if (it.exists()) it.delete()
                    encryptedFile?.openFileOutput()
                }

            } catch (exception: IOException) {
                Log.d("EncryptedFile:", exception.message.toString())
            }
        }
        verify_signature.setOnClickListener {
            val filePath = generateFileAndWriteLogs()?.path
            val data = filePath?.toByteArray(Charsets.UTF_8)
            try {
                if (data != null) {
                    verifySignature(data)
                }
            } catch (exception: IOException) {
                Log.d("Exception:", exception.toString())
            }
            textSignature.text = data?.let { byteArray -> verifySignature(byteArray).toString() }
        }
    }

    private fun verifySignature(data: ByteArray): Boolean {
        val realSignature = signDocument(privateKey, data)
        val encoded = Base64.encodeToString(realSignature, Base64.DEFAULT)
        Log.d("RealSignature", encoded)
        return verifySign(data, realSignature)
    }

    private fun generateFileAndWriteLogs(): File? {
        val directory = finalFile
        file = File(directory, FILE_NAME)
        val logger = Logger.GLOBAL_LOGGER_NAME
        val rootLogger = LogManager.getLogManager().getLogger(logger)
        val handlers = rootLogger.handlers
        if (handlers.isNullOrEmpty()) {
            try {
                fileHandler = FileHandler(file?.absolutePath, 5 * 1024 * 1024, 3, true)
                fileHandler?.apply {
                    formatter = SimpleFormatter()
                    level = Level.ALL
                    publish(LogRecord(Level.ALL, "Logs"))
                    rootLogger.addHandler(fileHandler as Handler)
                }
            } catch (exception: Exception) {
                Log.e(FILE_NAME, "FileHandler exception", exception)
            } finally {
                if (fileHandler != null) fileHandler?.close()
            }
        }
        return file
    }

    private val finalFile: File
        get() {
            val parent = applicationContext.filesDir.absolutePath
            val folder = File(parent, applicationContext.getString(R.string.app_name))
            if (!folder.exists()) {
                folder.mkdirs()
                folder.mkdir()
            }
            return folder
        }

    companion object {
        val PRIVATE_KEY_PEM = """-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQggJTXnmiG+VNXkdPr
ILylN+a6Gcia8Tf2JIRfOQOxGeqhRANCAARgY4WvJLgfONJUIjNzOxAdm/GjRCDZ
j4e8WV9m5Tr+8/qT+jqaMfBivIwCABcfPP8K3p31GyCT0l8Be/O/m6ZO
-----END PRIVATE KEY-----""".trimIndent()
        val PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYGOFryS4HzjSVCIzczsQHZvxo0Qg
2Y+HvFlfZuU6/vP6k/o6mjHwYryMAgAXHzz/Ct6d9Rsgk9JfAXvzv5umTg==
-----END PUBLIC KEY-----""".trimIndent()
    }

    private fun verifySign(data: ByteArray, realSignature: ByteArray) =
        verifySignature(publicKey, data, realSignature)

}
