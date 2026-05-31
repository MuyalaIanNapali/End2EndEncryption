package org.e2ee.data.remote.util

import android.util.Base64

fun String.toBase64(): ByteArray {
    return Base64.decode(this, Base64.DEFAULT)
}