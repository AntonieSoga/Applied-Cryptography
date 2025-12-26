# Little Christmas Gifts - Writeup

This challenge is a classic cryptography problem involving a Linear Congruential Generator (LCG). Because you have a Known Plaintext (the header), we can recover the internal state of the generator and predict all future outputs to decrypt the flag.

-> The Vulnerability: LCG Predictability

The script uses an LCG to generate a keystream. The formula for an LCG is:

```math
sn+1​≡(a⋅sn​+b)(modm)
```

While LCGs appear random, they are mathematically insecure if we can observe enough outputs. In this case:

```math
 m (the modulus) is a 64-bit prime.
 ```

 -> a (the multiplier) and b (the increment) are random 64-bit integers.

The Keystream is formed by concatenating these states.

Since we know the first 74 bytes of the plaintext (the header), we can XOR them with the first 74 bytes of `gifts.enc` to recover the first 9 states (s0​ through s8​).
Step-by-Step Solution
1. Recovering the Modulus (m)

    - If we take the differences between consecutive states (dn​=sn+1​−sn​), the increment b cancels out:
    ```math
    dn​≡a⋅dn−1​(modm)
    ```
    - By cross-multiplying dn​⋅dn−2​ and dn−12​, we get values that are all multiples of m. By calculating the Greatest Common Divisor (GCD) of these values, we can recover m.

2. Recovering a and b
    - Once we have m, a is found using a modular inverse:
    ```math
    a≡(s2​−s1​)⋅(s1​−s0​)−1(modm)
    ```
    - Then b is simply:

    ```math
    b≡(s1​−a⋅s0​)(modm)
    ```