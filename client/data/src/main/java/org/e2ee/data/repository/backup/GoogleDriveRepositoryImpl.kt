package org.e2ee.data.repository.backup

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.e2ee.common.Share
import org.json.JSONObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import javax.inject.Inject

class GoogleDriveRepositoryImpl @Inject constructor() : GoogleDriveRepository {

    override suspend fun uploadBackup(
        accessToken: String,
        encryptedBackup: ByteArray
    ) {
        upsertAppDataFile(
            accessToken = accessToken,
            fileName = BACKUP_FILE_NAME,
            mimeType = "application/octet-stream",
            content = encryptedBackup
        )
    }

    override suspend fun uploadShare(
        accessToken: String,
        share: Share
    ) {
        // Assumes Share is @Serializable. If it isn't, swap this for your own
        // serialization (see note below).
        val bytes = Json.encodeToString(share).encodeToByteArray()
        upsertAppDataFile(
            accessToken = accessToken,
            fileName = SHARE_FILE_NAME,
            mimeType = "application/json",
            content = bytes
        )
    }

    override suspend fun downloadBackup(accessToken: String): ByteArray? {
        return downloadAppDataFile(accessToken, BACKUP_FILE_NAME)
    }

    override suspend fun downloadShare(accessToken: String): Share? {
        val bytes = downloadAppDataFile(accessToken, SHARE_FILE_NAME) ?: return null
        Log.i("GoogleDriveRepositoryImpl", "Downloaded share bytes: ${bytes.size}")
        return Json.decodeFromString<Share>(bytes.decodeToString())
    }

    /**
     * Creates the file in appDataFolder if it doesn't exist, otherwise updates it.
     * Keeps a single file per name instead of piling up duplicates.
     */
    private suspend fun upsertAppDataFile(
        accessToken: String,
        fileName: String,
        mimeType: String,
        content: ByteArray
    ) = withContext(Dispatchers.IO) {
        val existingId = findFileId(accessToken, fileName)
        if (existingId == null) {
            createFile(accessToken, fileName, mimeType, content)
        } else {
            updateFile(accessToken, existingId, mimeType, content)
        }
    }

    /** Returns the id of a file in appDataFolder with the given name, or null. */
    private fun findFileId(accessToken: String, fileName: String): String? {
        val q = URLEncoder.encode("name = '$fileName'", "UTF-8")
        val url = URL(
            "https://www.googleapis.com/drive/v3/files" +
                    "?spaces=appDataFolder&q=$q&fields=files(id,name)"
        )
        val conn = (url.openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            setRequestProperty("Authorization", "Bearer $accessToken")
        }

        val code = conn.responseCode
        if (code !in 200..299) failWith(conn, code, "search")

        val body = conn.inputStream.bufferedReader().use { it.readText() }
        val files = JSONObject(body).optJSONArray("files")
        return if (files != null && files.length() > 0) {
            files.getJSONObject(0).getString("id")
        } else {
            null
        }
    }

    /** Multipart create: metadata (with appDataFolder parent) + media in one request. */
    private fun createFile(
        accessToken: String,
        fileName: String,
        mimeType: String,
        content: ByteArray
    ) {
        val boundary = "----e2eeBackup${System.currentTimeMillis()}"
        val metadata = """{"name":"$fileName","parents":["appDataFolder"]}"""

        val conn = (URL(
            "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart"
        ).openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            doOutput = true
            setRequestProperty("Authorization", "Bearer $accessToken")
            setRequestProperty("Content-Type", "multipart/related; boundary=$boundary")
        }

        conn.outputStream.use { out ->
            out.write("--$boundary\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n$metadata\r\n".toByteArray())
            out.write("--$boundary\r\nContent-Type: $mimeType\r\n\r\n".toByteArray())
            out.write(content)
            out.write("\r\n--$boundary--\r\n".toByteArray())
        }

        val code = conn.responseCode
        if (code !in 200..299) failWith(conn, code, "create")
    }

    /**
     * Replaces the bytes of an existing file. HttpURLConnection can't send PATCH
     * directly, so we POST with Google's method-override header.
     */
    private fun updateFile(
        accessToken: String,
        fileId: String,
        mimeType: String,
        content: ByteArray
    ) {
        val conn = (URL(
            "https://www.googleapis.com/upload/drive/v3/files/$fileId?uploadType=media"
        ).openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            doOutput = true
            setRequestProperty("Authorization", "Bearer $accessToken")
            setRequestProperty("X-HTTP-Method-Override", "PATCH")
            setRequestProperty("Content-Type", mimeType)
        }

        conn.outputStream.use { it.write(content) }

        val code = conn.responseCode
        if (code !in 200..299) failWith(conn, code, "update")
    }

    private fun failWith(conn: HttpURLConnection, code: Int, op: String): Nothing {
        val err = conn.errorStream?.bufferedReader()?.readText().orEmpty()
        throw IOException("Drive $op failed ($code): $err")
    }

    /**
     * Finds a file by name in appDataFolder and returns its raw bytes,
     * or null if no such file exists. Throws on transport/permission errors.
     */
    private suspend fun downloadAppDataFile(
        accessToken: String,
        fileName: String
    ): ByteArray? = withContext(Dispatchers.IO) {
        val fileId = findFileId(accessToken, fileName) ?: return@withContext null
        downloadFileContent(accessToken, fileId)
    }

    /** Downloads the media (raw bytes) of a Drive file by id. */
    private fun downloadFileContent(accessToken: String, fileId: String): ByteArray {
        val conn = (URL(
            "https://www.googleapis.com/drive/v3/files/$fileId?alt=media"
        ).openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            setRequestProperty("Authorization", "Bearer $accessToken")
        }

        val code = conn.responseCode
        if (code !in 200..299) failWith(conn, code, "download")

        return conn.inputStream.use { it.readBytes() }
    }

    private companion object {
        const val BACKUP_FILE_NAME = "backup.enc"
        const val SHARE_FILE_NAME = "share.json"
    }
}