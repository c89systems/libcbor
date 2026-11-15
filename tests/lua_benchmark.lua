-- One native transfer call. No DATA tokens, strings or tables cross the VM.
local c = require('cbor')
local transfer = c.transfer(native_source, native_sink, c.SEQUENCE)
assert(transfer:run() == c.DONE)
local read, written = transfer:counts()
assert(read == 1027*65536 and written == read)
