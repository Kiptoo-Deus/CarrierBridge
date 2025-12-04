package com.example.carrierbridge_android.data

import android.content.Context
import android.provider.ContactsContract
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.URL
import java.security.MessageDigest

class ContactRepository(private val context: Context) {
    private val tag = "ContactRepository"

    companion object {
        const val SERVER_URL = "http:

    }

    suspend fun getDeviceContacts(): Result<List<DeviceContact>> {
        return withContext(Dispatchers.IO) {
            try {
                val contacts = mutableListOf<DeviceContact>()
                val contentResolver = context.contentResolver

                val cursor = contentResolver.query(
                    ContactsContract.Contacts.CONTENT_URI,
                    arrayOf(
                        ContactsContract.Contacts._ID,
                        ContactsContract.Contacts.DISPLAY_NAME
                    ),
                    null,
                    null,
                    null
                )

                cursor?.use { cur ->
                    val idIndex = cur.getColumnIndex(ContactsContract.Contacts._ID)
                    val nameIndex = cur.getColumnIndex(ContactsContract.Contacts.DISPLAY_NAME)

                    while (cur.moveToNext()) {
                        val contactId = cur.getString(idIndex)
                        val displayName = cur.getString(nameIndex)

                        val phones = getPhoneNumbers(contactId)

                        val emails = getEmails(contactId)

                        if (phones.isNotEmpty() || emails.isNotEmpty()) {
                            contacts.add(
                                DeviceContact(
                                    id = contactId,
                                    displayName = displayName,
                                    phones = phones,
                                    emails = emails
                                )
                            )
                        }
                    }
                }

                Log.d(tag, "Loaded ${contacts.size} device contacts")
                Result.success(contacts)
            } catch (e: Exception) {
                Log.e(tag, "Failed to read device contacts", e)
                Result.failure(e)
            }
        }
    }

    private fun getPhoneNumbers(contactId: String): List<String> {
        val phones = mutableListOf<String>()
        val contentResolver = context.contentResolver

        val phoneCursor = contentResolver.query(
            ContactsContract.CommonDataKinds.Phone.CONTENT_URI,
            arrayOf(ContactsContract.CommonDataKinds.Phone.NUMBER),
            "${ContactsContract.CommonDataKinds.Phone.CONTACT_ID} = ?",
            arrayOf(contactId),
            null
        )

        phoneCursor?.use { cur ->
            val phoneIndex = cur.getColumnIndex(ContactsContract.CommonDataKinds.Phone.NUMBER)
            while (cur.moveToNext()) {
                val phone = cur.getString(phoneIndex)
                if (phone != null) {
                    phones.add(normalizePhoneNumber(phone))
                }
            }
        }

        return phones
    }

    private fun getEmails(contactId: String): List<String> {
        val emails = mutableListOf<String>()
        val contentResolver = context.contentResolver

        val emailCursor = contentResolver.query(
            ContactsContract.CommonDataKinds.Email.CONTENT_URI,
            arrayOf(ContactsContract.CommonDataKinds.Email.ADDRESS),
            "${ContactsContract.CommonDataKinds.Email.CONTACT_ID} = ?",
            arrayOf(contactId),
            null
        )

        emailCursor?.use { cur ->
            val emailIndex = cur.getColumnIndex(ContactsContract.CommonDataKinds.Email.ADDRESS)
            while (cur.moveToNext()) {
                val email = cur.getString(emailIndex)
                if (email != null) {
                    emails.add(email.lowercase())
                }
            }
        }

        return emails
    }

    private fun normalizePhoneNumber(phone: String): String {
        var normalized = phone.replace(Regex("[^0-9+]"), "")

        if (!normalized.startsWith("+") && normalized.length == 10) {
            normalized = "+1$normalized"
        } else if (!normalized.startsWith("+")) {
            normalized = "+$normalized"
        }
        return normalized
    }

    suspend fun discoverAvailableContacts(
        deviceContacts: List<DeviceContact>,
        authToken: String
    ): Result<List<AvailableContact>> {
        return withContext(Dispatchers.IO) {
            try {

                val hashedContacts = mutableListOf<String>()

                for (contact in deviceContacts) {
                    for (phone in contact.phones) {
                        hashedContacts.add(hashPhoneNumber(phone))
                    }
                    for (email in contact.emails) {
                        hashedContacts.add(hashEmail(email))
                    }
                }

                if (hashedContacts.isEmpty()) {
                    return@withContext Result.success(emptyList())
                }

                val requestBody = """{"hashed_contacts":${buildJsonArray(hashedContacts)}}"""
                val response = makeHttpRequest(
                    "$SERVER_URL/api/contacts/discover",
                    "POST",
                    requestBody,
                    "Bearer $authToken"
                )

                if (response != null) {
                    val contacts = parseAvailableContacts(response, deviceContacts)
                    Log.d(tag, "Discovered ${contacts.size} available contacts")
                    Result.success(contacts)
                } else {
                    Result.failure(Exception("Contact discovery failed"))
                }
            } catch (e: Exception) {
                Log.e(tag, "Failed to discover contacts", e)
                Result.failure(e)
            }
        }
    }

    private fun hashPhoneNumber(phone: String): String {
        return sha256Hash(phone)
    }

    private fun hashEmail(email: String): String {
        return sha256Hash(email.lowercase())
    }

    private fun sha256Hash(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(input.toByteArray())
        return hash.joinToString("") { "%02x".format(it) }
    }

    private fun makeHttpRequest(
        urlString: String,
        method: String,
        body: String = "",
        authHeader: String = ""
    ): String? {
        return try {
            val url = URL(urlString)
            val conn = url.openConnection() as? java.net.HttpURLConnection ?: return null

            conn.requestMethod = method
            conn.setRequestProperty("Content-Type", "application/json")
            conn.setRequestProperty("Accept", "application/json")
            if (authHeader.isNotEmpty()) {
                conn.setRequestProperty("Authorization", authHeader)
            }
            conn.connectTimeout = 10000
            conn.readTimeout = 10000

            if (body.isNotEmpty()) {
                conn.outputStream.use { output ->
                    output.write(body.toByteArray())
                    output.flush()
                }
            }

            val statusCode = conn.responseCode
            if (statusCode in 200..299) {
                conn.inputStream.bufferedReader().use { it.readText() }
            } else {
                Log.e(tag, "HTTP error: $statusCode")
                null
            }
        } catch (e: Exception) {
            Log.e(tag, "HTTP request failed", e)
            null
        }
    }

    private fun parseAvailableContacts(json: String, deviceContacts: List<DeviceContact>): List<AvailableContact> {
        val available = mutableListOf<AvailableContact>()

        try {

            val contactsStart = json.indexOf("\"contacts\":")
            if (contactsStart == -1) return available

            val arrayStart = json.indexOf("[", contactsStart)
            val arrayEnd = json.lastIndexOf("]")
            if (arrayStart == -1 || arrayEnd == -1) return available

            val contactsJson = json.substring(arrayStart + 1, arrayEnd)

            var currentObject = ""
            var braceCount = 0

            for (char in contactsJson) {
                currentObject += char
                if (char == '{') braceCount++
                if (char == '}') {
                    braceCount--
                    if (braceCount == 0 && currentObject.contains("user_id")) {
                        val contact = parseContactJson(currentObject)
                        if (contact != null) {
                            available.add(contact)
                        }
                        currentObject = ""
                    }
                }
            }
        } catch (e: Exception) {
            Log.e(tag, "Failed to parse contacts JSON", e)
        }

        return available
    }

    private fun parseContactJson(json: String): AvailableContact? {
        return try {
            val userId = extractJsonString(json, "user_id") ?: return null
            val displayName = extractJsonString(json, "display_name") ?: "User"
            val phone = extractJsonString(json, "phone")
            val email = extractJsonString(json, "email")
            val online = json.contains("\"online\":true")
            val lastSeen = extractJsonLong(json, "last_seen") ?: 0

            AvailableContact(userId, displayName, phone, email, online, lastSeen)
        } catch (e: Exception) {
            null
        }
    }

    private fun buildJsonArray(items: List<String>): String {
        return "[" + items.joinToString(",") { "\"$it\"" } + "]"
    }

    private fun extractJsonString(json: String, key: String): String? {
        val pattern = "\"$key\"\\s*:\\s*\"([^\"]*)\""
        val regex = Regex(pattern)
        return regex.find(json)?.groupValues?.get(1)
    }

    private fun extractJsonLong(json: String, key: String): Long? {
        val pattern = "\"$key\"\\s*:\\s*(\\d+)"
        val regex = Regex(pattern)
        return regex.find(json)?.groupValues?.get(1)?.toLongOrNull()
    }
}

data class DeviceContact(
    val id: String,
    val displayName: String,
    val phones: List<String> = emptyList(),
    val emails: List<String> = emptyList()
)

data class AvailableContact(
    val userId: String,
    val displayName: String,
    val phone: String? = null,
    val email: String? = null,
    val online: Boolean = false,
    val lastSeen: Long = 0
)
