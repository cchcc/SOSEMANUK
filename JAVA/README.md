SOSEMANUK stream cipher Java implementations.


The SOSEMANUK stream cipher has been invented by Come Berbain, Olivier
Billet, Nicolas Courtois, Henri Gilbert, Louis Goubin, Aline Gouget,
Louis Granboulan, Cedric Lauradoux, Marine Minier, Thomas Pornin
and Herve Sibert. The Java implementations are intended to illustrate
the internal functioning and possible implementation techniques for
the SOSEMANUK stream cipher in Java.


The Java implementations are free software; their license is as close
to Public Domain as any software license can be under French law.



Two implementations are provided; each consists of a single Java
source file: SosemanukFast.java and SosemanukSlow.java


Those two implementations are independant. Each can be used from
external packages through four public methods:


-- A public constructor with no argument.


-- void setKey(byte[] key): sets the private key. The private key is
any byte array, of length between 1 and 32 bytes (inclusive). Note that
the SOSEMANUK aims only at 128-bit equivalent security, even if a
longer private key is used.


-- void setIV(byte[] iv): sets the "initial value", which is a byte
array whose length is between 0 and 16 bytes (inclusive). The IV is
a non-secret convention between the sender and the receiver.


-- void makeStream(byte[] buf, int off, int len): computes the next
"len" bytes of output stream, and store them in "buf" at offset "off".


These objects use no mutable global contents; hence, several instances
may be used simultaneously by distinct threads.

Both files contain a static "main()" method, and are thus
stand-alone applications. These "main()" methods output the first 160
bytes of generated stream from the following 40-bit private key and

128-bit IV:

key = A7 C0 83 FE B7

IV  = 00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF



SosemanukSlow.java contains a pedagogical implementation which tries to
mimic the abstract mathematical description of the SOSEMANUK cipher. In
particular, it maintains the current internal LFSR in an array of ten
"int" values which are really "shifted" (the values are moved around in
memory). A consequence is that this implementation is not very fast.


SosemanukFast.java contains an optimized implementation, which unrolls
the central loop over 20 steps. The LFSR internal state is stored into
ten instance variables, which are never moved. The SosemanukFast.java
implementation is deemed appropriate for most purposes.
