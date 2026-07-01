package org.e2ee.crypto.backup.shamirSecretSharing

import org.e2ee.common.Share
import org.e2ee.crypto.backup.shamirSecretSharing.ByteUtils.bigIntegerToByteArray
import java.math.BigInteger

class RecoverSecret {
    val PRIME: BigInteger = BigInteger(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
        16
    )

    fun recoverSecret(
        shares: List<Share>,
        prime: BigInteger = PRIME
    ): ByteArray {

        require(shares.size >= 2)

        val xs = shares.map {
            BigInteger.valueOf(it.index.toLong())
        }

        val ys = shares.map {
            ByteUtils.byteArrayToBigInteger(it.value)
        }

        val secret = lagrangeInterpolate(
            BigInteger.ZERO,
            xs,
            ys,
            prime
        )

        return bigIntegerToByteArray(secret)
    }

    private fun extendedGCD(a: BigInteger, b: BigInteger): Pair<BigInteger, BigInteger> {

        var aa = a
        var bb = b

        var x = BigInteger.ZERO
        var lastX = BigInteger.ONE

        var y = BigInteger.ONE
        var lastY = BigInteger.ZERO

        while (bb != BigInteger.ZERO) {

            val quotient = aa.divide(bb)

            val tempA = aa
            aa = bb
            bb = tempA.mod(bb)

            val tempX = x
            x = lastX.subtract(quotient.multiply(x))
            lastX = tempX

            val tempY = y
            y = lastY.subtract(quotient.multiply(y))
            lastY = tempY
        }

        return Pair(lastX, lastY)
    }

    private fun product(values: List<BigInteger>): BigInteger {

        var result = BigInteger.ONE

        values.forEach {
            result = result.multiply(it)
        }

        return result
    }

    private fun divMod(
        num: BigInteger,
        den: BigInteger,
        prime: BigInteger
    ): BigInteger {

        val (inverse, _) = extendedGCD(den, prime)

        return num.multiply(inverse).mod(prime)
    }

    private fun lagrangeInterpolate(
        x: BigInteger,
        xValues: List<BigInteger>,
        yValues: List<BigInteger>,
        prime: BigInteger
    ): BigInteger {

        require(xValues.distinct().size == xValues.size) {
            "Points must be distinct"
        }

        val nums = mutableListOf<BigInteger>()
        val dens = mutableListOf<BigInteger>()

        for (i in xValues.indices) {

            val others = xValues.toMutableList()
            val current = others.removeAt(i)

            nums.add(product(others.map { x.subtract(it) }))
            dens.add(product(others.map { current.subtract(it) }))
        }

        val denominator = product(dens)

        var numerator = BigInteger.ZERO

        for (i in xValues.indices) {

            val term = divMod(
                nums[i]
                    .multiply(denominator)
                    .multiply(yValues[i])
                    .mod(prime),
                dens[i],
                prime
            )

            numerator = numerator.add(term)
        }

        return divMod(numerator, denominator, prime)
            .add(prime)
            .mod(prime)
    }
}