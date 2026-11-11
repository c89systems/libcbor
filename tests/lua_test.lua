local c = require('cbor')
local runtime = c.create({step_input=3, step_output=5, step_events=2})
assert(runtime:version() == expected_version)
assert(runtime:default_options().chunk == 0) -- zero selects the C default
local allocator = runtime:default_allocator()
local child_runtime = c.create({allocator=allocator})
assert(allocator:close() == c.INVALID)
local child_decoder = child_runtime:decoder_create()
local child_reader = child_runtime:reader_create()
local child_fd = child_runtime:fd_create(0)
assert(child_runtime:close() == c.INVALID)
assert(child_decoder:close() == c.OK and child_reader:close() == c.OK and child_fd:close() == c.OK)
assert(child_runtime:close() == c.OK and allocator:close() == c.OK)
local in_place = c.init()
assert(in_place:close() == c.OK)
local function complete(operation)
  for step=1,10000 do
    local status, diagnostic = operation:step()
    if status == c.DONE then
      local rc, progress = operation:progress()
      assert(rc == c.OK and progress.records == 1)
      assert(operation:diagnostic() == c.OK)
      return
    end
    assert(status == c.OK or status == c.INPUT or status == c.OUTPUT, diagnostic.message)
  end
  error('conversion stalled')
end
for _, name in ipairs({'json_to_cbor', 'cbor_to_json', 'encode_map', 'decode_map'}) do
  local mode = name == 'json_to_cbor' and 1 or name == 'cbor_to_json' and 2 or name == 'encode_map' and 3 or 4
  local first, second = native_case(mode)
  local operation, status, diagnostic = runtime[name .. '_init'](runtime, first, second, {chunk=1, step_events=2})
  assert(operation, diagnostic and diagnostic.message)
  assert(first:close() == c.INVALID and second:close() == c.INVALID and runtime:close() == c.INVALID)
  complete(operation)
  assert(operation:close() == c.OK)
  assert(first:close() == c.OK and second:close() == c.OK)
  first, second = native_case(mode)
  operation = assert(runtime[name .. '_open'](runtime, first, second))
  repeat
    status, diagnostic = operation:run()
    assert(status == c.INPUT or status == c.OUTPUT or status == c.DONE, diagnostic.message)
  until status == c.DONE
  assert(operation:close() == c.OK and first:close() == c.OK and second:close() == c.OK)
  first, second = native_case(mode, false)
  status, diagnostic = runtime[name](runtime, first, second)
  assert(status == c.OK, diagnostic.message)
  assert(first:close() == c.OK and second:close() == c.OK)
end
assert(runtime:close() == c.OK)
do
  local owner = c.create({allocator=counting_allocator})
  local first, second = native_case(1)
  local operation = owner:json_to_cbor_open(first, second)
  -- Finalization must release the child before destroying its native root.
  assert(operation:step() >= c.OK)
end
collectgarbage('collect')
do
  local owner = c.create({allocator=counting_allocator})
  local heap = owner:encoder_create()
  assert(heap:put(c.token(c.BYTES, 3)) == c.OK)
  local status, borrowed = heap:peek()
  assert(status == c.OUTPUT and borrowed:length() == 1)
  assert(heap:reset() == c.BUSY and heap:close() == c.INVALID)
  assert(borrowed:close() == c.OK)
  assert(heap:advance(1) == c.OK)
  assert(heap:put(c.token(c.DATA, 0, 'abc')) == c.OK)
  local rc, span = heap:peek()
  assert(rc == c.OUTPUT and span:string() == 'abc')
  -- Leave root, heap encoder, token and borrowed span to finalization.
end
collectgarbage('collect')
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
local tagged = c.encoder()
assert(tagged:tag(55799) == c.OK)
assert(tagged:read() == c.OK)
assert(tagged:put(c.token(c.UINT, 42)) == c.OK)
assert(tagged:end_tag() == c.OUTPUT)
assert(tagged:read() == c.OK)
assert(tagged:end_tag() == c.OK and tagged:finish() == c.OK)
local tag_decoder = c.decoder()
local status, used, number = tag_decoder:next_tag(string.char(0xd9,0xd9,0xf7))
assert(status == c.TOKEN and used == 3 and number == 55799)
assert(tag_decoder:close() == c.OK and tagged:close() == c.OK)
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

-- All COSE payload I/O remains on the native source/sink callbacks.
do
  local owner = c.create({allocator=counting_allocator})
  assert(owner:default_cose_options().record_bytes == 2048)
  local content = assert(owner:cose_key_init(c.COSE_A256GCM, string.rep('\0',32)))
  local wrap = assert(owner:cose_key_create(c.COSE_A256KW, string.rep('w',32), 'wrap'))
  local private = assert(owner:cose_key_create(c.COSE_X25519_PRIVATE, string.rep('x',32), 'x'))
  local rc, public_bytes = private:public_key()
  assert(rc == c.OK and #public_bytes == 32)
  local public = assert(owner:cose_key_init(c.COSE_X25519_PUBLIC, public_bytes, 'x'))
  local status, info = wrap:metadata()
  assert(status == c.OK and info.kind == c.COSE_A256KW and info.key_id == 'wrap')
  assert(content:public_key() == c.UNSUPPORTED)
  assert(content:diagnostic() == c.OK)
  local bad, why = owner:cose_key_init(c.COSE_A256GCM, 'short')
  assert(bad == nil and why == c.INVALID)
  local function finish(op)
    for step=1,10000 do
      local status, diagnostic = op:run()
      if status == c.DONE then return end
      assert(status == c.INPUT or status == c.OUTPUT, diagnostic.layer)
    end
    error('COSE stalled')
  end
  for _, stream in ipairs({false, true}) do
    for _, encrypt in ipairs({false, true}) do
      local seal = stream and 'cose_encrypt_stream' or encrypt and 'cose_encrypt' or 'cose_encrypt0'
      local open = stream and 'cose_decrypt_stream' or 'cose_decrypt'
      for _, mode in ipairs({'_init', '_open', ''}) do
        local source, sink = native_case(1, mode ~= '')
        local keys = encrypt and {wrap, public} or stream and {content} or content
        local aad = c.span('application context')
        local options = {encrypt=encrypt, aad=aad, record_bytes=stream and 16 or 2048,
                         step_input=11, step_output=7, step_events=3}
        if mode == '' then
          assert(owner[seal](owner, source, sink, keys, options) == c.OK)
        else
          local op = assert(owner[seal..mode](owner, source, sink, keys, options))
          -- Mutation must not invalidate captured pointers or key wrapper pins.
          options.aad = 'changed'; options.encrypt = false
          if type(keys) == 'table' then keys[1] = nil; keys[2] = nil end
          assert(aad:close() == c.INVALID)
          assert((encrypt and wrap or content):close() == c.INVALID)
          assert(source:close() == c.INVALID and sink:close() == c.INVALID)
          collectgarbage('collect')
          finish(op)
          assert(op:step() == c.DONE and op:progress() == c.OK)
          assert(op:next() == c.UNSUPPORTED) -- sealing operations cannot resume
          assert(op:cleanup() == c.OK and op:destroy() == c.OK)
        end
        assert(aad:close() == c.OK)
        assert(source:close() == c.OK and sink:close() == c.OK)
        source, sink = native_case(2, mode ~= '')
        local receive_options = {aad='application context', record_bytes=stream and 16 or 2048}
        if mode == '' then
          assert(owner[open](owner, source, sink, encrypt and private or content, receive_options) == c.OK)
        else
          local op = assert(owner[open..mode](owner, source, sink, encrypt and private or content, receive_options))
          assert(op:stream_info() == (stream and c.INPUT or c.UNSUPPORTED))
          finish(op)
          local info_status, stream_info = op:stream_info()
          if stream then
            assert(info_status == c.OK and #stream_info.stream_id == 16 and stream_info.complete and stream_info.encrypt == encrypt)
          else assert(info_status == c.UNSUPPORTED and stream_info == nil) end
          assert(op:next(nil, {record_bytes=1}) == c.INVALID)
          assert(op:next() == c.OK)
          local terminal
          repeat terminal = op:run() until terminal ~= c.INPUT and terminal ~= c.OUTPUT
          assert(terminal == c.MALFORMED)
          assert(op:close() == c.OK)
        end
        assert(source:close() == c.OK and sink:close() == c.OK)
      end
    end
  end
  assert(public:close() == c.OK and private:close() == c.OK)
  assert(wrap:close() == c.OK and content:close() == c.OK and owner:close() == c.OK)
end
-- Exercise deferred finalization of keys, options, endpoints and both shell
-- ownership modes without explicit close or a stable user recipient table.
do
  local root = c.create({allocator=counting_allocator})
  local key = root:cose_key_create(c.COSE_A256KW, string.rep('k',32))
  local source, sink = native_case(1)
  local op = root:cose_encrypt_open(source, sink, {key}, {aad=c.span('context')})
  assert(op:step() >= c.OK)
end
collectgarbage('collect')
