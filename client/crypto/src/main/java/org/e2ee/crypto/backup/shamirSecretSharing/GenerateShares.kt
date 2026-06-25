package org.e2ee.crypto.backup.shamirSecretSharing

import org.e2ee.common.Share
import java.math.BigInteger
import java.security.SecureRandom

class GenerateShares {
    val PRIME: BigInteger = BigInteger(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
        16
    )

    private val random = SecureRandom()

    fun makeRandomShares(
        secret: ByteArray,
        minimum: Int,
        shares: Int,
        prime: BigInteger = PRIME
    ): List<Share> {

        // Convert bytes to positive BigInteger
        val secretInt = BigInteger(1, secret)

        require(secretInt < prime) {
            "Secret is larger than prime."
        }

        require(minimum <= shares) {
            "Pool secret would be irrecoverable."
        }

        val polynomial = mutableListOf<BigInteger>()
        polynomial.add(secretInt)

        repeat(minimum - 1) {
            polynomial.add(randomBigInteger(prime))
        }

        return (1..shares).map {
            Share(
                it,
                value = ByteUtils.bigIntegerToByteArray(
                    evalAt(
                        polynomial,
                        BigInteger.valueOf(it.toLong()),
                        prime
                    )
                )
            )
        }
    }

    /**
     * Generate a random BigInteger between 0 and PRIME-1
     */
    private fun randomBigInteger(max: BigInteger): BigInteger {
        var r: BigInteger
        do {
            r = BigInteger(max.bitLength(), random)
        } while (r >= max)
        return r
    }

    private fun evalAt(
        polynomial: List<BigInteger>,
        x: BigInteger,
        prime: BigInteger
    ): BigInteger {

        var accum = BigInteger.ZERO

        for (coeff in polynomial.asReversed()) {
            accum = accum.multiply(x).add(coeff).mod(prime)
        }

        return accum
    }
}