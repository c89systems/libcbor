local c = require('cbor')
assert(c.version() == expected_version)
assert(c.status_string(c.MALFORMED):find('CBOR'))
local frames = c.frames(4)
local d, e = c.decoder(frames, 2), c.encoder(nil, 1)
assert(frames:close() == c.INVALID)
local inputs = {string.char(0x82), string.char(0x62), 'a', 'b', string.char(0xf9,0x7e,1)}
local output = {}
local data_span
for _, bytes in ipairs(inputs) do
  while true do
    local rc, used, token = d:next(bytes)
    bytes = bytes:sub(used+1)
    if rc == c.TOKEN then
      assert(e:put(token) == c.OK)
      if token:kind() == c.DATA then
        data_span = token:span()
        assert(data_span:length() == 1)
        collectgarbage()
        assert(data_span:string() == 'a' or data_span:string() == 'b')
      end
      repeat
        local wr, fragment = e:read(1)
        output[#output+1] = fragment
        assert(wr == c.OK or wr == c.OUTPUT)
        if wr == c.OK then break end
      until false
    elseif rc == c.INPUT or rc == c.DONE then break
    else error(c.status_string(rc)) end
  end
end
assert(table.concat(output) == table.concat(inputs))
assert(d:finish() == c.OK and e:finish() == c.OK)
assert(d:reset() == c.OK and e:reset() == c.OK)
assert(d:close() == c.OK and e:close() == c.OK)
assert(frames:close() == c.OK)
assert(data_span:string() == 'b') -- borrowed input stays pinned after codec close
assert(not pcall(function() d:next('a') end))
for kind = c.UINT, c.FLOAT64 do
  local t = c.token(kind, 0)
  assert(t:kind() == kind and t:argument() == 0 and not t:indefinite())
end
local t = c.token(c.FLOAT64)
assert(t:float64_set(1.5) == c.OK)
local rc, value = t:float64_get()
assert(rc == c.OK and value == 1.5)
local span = c.span('abc')
assert(span:string() == 'abc' and span:length() == 3)
local r = c.reader(c.LENGTH32)
local rc, prefix = c.length32(1)
assert(rc == c.OK and prefix == string.char(0,0,0,1))
local bytes = prefix .. string.char(0)
local events = {}
repeat
  local status, used, event = r:next(bytes)
  bytes = bytes:sub(used+1)
  if status == c.TOKEN then events[#events+1] = event.type
  elseif status == c.INPUT then break
  else error(c.status_string(status)) end
until false
assert(#events == 3 and events[1] == c.RECORD_BEGIN and events[3] == c.RECORD_END)
assert(r:finish() == c.OK)
local rc = c.length32(0)
assert(rc == c.LIMIT)
local hd, he = c.decoder_create(), c.encoder_create()
assert(hd:close() == c.OK and hd:close() == c.OK and he:close() == c.OK)
local owner = c.span('payload')
do
  local encoder = c.encoder()
  assert(encoder:put(c.token(c.BYTES, owner:length())) == c.OK)
  assert(encoder:read() == c.OK)
  local token = c.token(c.DATA, 0, owner)
  assert(encoder:put(token) == c.OK)
  assert(token:close() == c.INVALID and owner:close() == c.INVALID)
  -- The newer token finalizes before the encoder. Its pin still must release.
end
collectgarbage('collect')
assert(owner:close() == c.OK)
local fd = c.fd(0)
local fs, fw = fd:source(), fd:sink()
assert(fd:close() == c.INVALID)
assert(fs:close() == c.OK and fw:close() == c.OK and fd:close() == c.OK)
local pump = c.transfer(native_source, native_sink, c.SEQUENCE)
assert(native_source:close() == c.INVALID)
assert(pump:run() == c.DONE)
local read, written = pump:counts()
assert(read == written and read == 1027*65536)
assert(pump:step() == c.DONE)
assert(pump:close() == c.OK)
assert(native_source:close() == c.OK and native_sink:close() == c.OK)
collectgarbage()
