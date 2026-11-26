( Return serialized locking Script. Native CHECKSIG validates the key at spend time. )
: p2pk-lock ( bytes -- bytes )
    33 bytes-check-size
    bytes-hex 21 swap bytes-cat bytes-hex ac bytes-cat ;
