# liger

Liger is a bridge from Go to the RELIC pairing based cryptography library inspired by Nik-U's wrapper for another pairing-based cryptography library. 


## Why use liger over PBC?

While PBC is an awesome, stable codebase, it doesn't appear to be actively developed, and appears to be quite a bit slower. We chose to implement this library after comparing RELIC and PBC's internal benchmarks, and after the attacks discovered on BN256 indicated that Go's PBC library is not adequate.

## Installation
First, install RELIC, as well as the shared library that comes with it.

Your relic build command must include -DALLOC=DYNAMIC. Dynamic allocation might be slower, but otherwise all variables are allocated on the stack which causes a number of issues with the bridge.

Liger does not require a particular set of curve parameters, but:
1. Liger does not support changing the curve beyond what is done at compile-time in RELIC
2. Liger has currently only seen extensive testing using BLS with a 381-bit prime as well as BN-256. 
3. As it cannot easily be determined a-priori, Liger assumes and enforces semantics that the pairing is asymmetric. Liger doesn't allow for arithmetic between groups G1 and G2 of G1 x G2 -> GT. Most, if not all, cryptographic protocols seem to work with this environment.

If you're having a hard time deciding on what compilation parameters to use, I'd suggest installing (gmp)[https://gmplib.org/] and using the following flags:
```
cmake -DMULTI=PTHREAD -DCORES=4 -DALLOC=DYNAMIC -DFP_PRIME=381 -ARITH=gmp-sec <directory>
```

#TODO:

- Currently, there is a weird abstraction barrier issue -- no outside user should be able to create a new G1 or G2 element by calling Make, and instead use the NewG1 and NewG2 function calls. Making will inherently break the memory management going on.
