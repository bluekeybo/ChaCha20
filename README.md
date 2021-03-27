# ChaCha20 Cipher
This is a ChaCha20 cipher implementation in Python.

I have tried two different ways to optimize the code and get a faster run:

1. Regular:
   This is the unoptimized version of the code -- slow.
2. Parallelized and Numba:
   This version uses parallelization thorugh multiprocessing and [Numba](https://numba.pydata.org/), a JIT compiler that translates a subset of Python and NumPy code into fast machine code -- faster.

Learn more about ChaCha20:
* [ChaCha20](https://en.wikipedia.org/wiki/Salsa20)
* [ChaCha20 Explained](https://www.youtube.com/watch?v=UeIpq-C-GSA)
* [ChaCha20 and Poly1305 for IETF Protocols](https://tools.ietf.org/html/rfc8439)
* [The design of Chacha20](https://loup-vaillant.fr/tutorials/chacha20-design)