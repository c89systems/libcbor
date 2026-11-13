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
-- Option lookups can execute Lua. Closed arguments must be rejected before
-- native construction, including keys in the private recipient snapshot.
do
  local function closes_argument(invoke, close, defaults, expected)
    local called = false
    local options = setmetatable(defaults or {}, {__index=function()
      if not called then
        called = true
        close()
        collectgarbage('collect')
      end
    end})
    local ok, err = pcall(invoke, options)
    assert(called and not ok and tostring(err):find(expected or 'handle is closed', 1, true), tostring(err))
  end
  local function rejects_bad_options(invoke)
    for _, raises in ipairs({false, true}) do
      local marker = {}
      local options = setmetatable({}, {__index=function()
        if raises then error(marker, 0) end
        return 'invalid size'
      end})
      local ok, err = pcall(invoke, options)
      assert(not ok and (not raises or err == marker))
    end
  end
  for mode, name in ipairs({'json_to_cbor', 'cbor_to_json', 'encode_map', 'decode_map'}) do
    for _, suffix in ipairs({'_init', '_open', ''}) do
      for target=1,3 do
        local root = c.create({allocator=counting_allocator})
        local first, second = native_case(mode, false)
        local arguments = {first, second, root}
        closes_argument(function(options)
          return root[name..suffix](root, first, second, options)
        end, function() assert(arguments[target]:close() == c.OK) end)
        assert(first:close() == c.OK and second:close() == c.OK and root:close() == c.OK)
      end
      local root = c.create({allocator=counting_allocator})
      local first, second = native_case(mode, false)
      rejects_bad_options(function(options)
        return root[name..suffix](root, first, second, options)
      end)
      assert(first:close() == c.OK and second:close() == c.OK and root:close() == c.OK)
    end
  end
  -- Closing a source also releases its heap-owned fd callback context.
  for _, suffix in ipairs({'_init', '_open', ''}) do
    local root = c.create({allocator=counting_allocator})
    local fd = root:fd_create(0)
    local source = fd:source()
    local unused, sink = native_case(1, false)
    closes_argument(function(options)
      return root['cbor_to_json'..suffix](root, source, sink, options)
    end, function()
      assert(source:close() == c.OK and fd:close() == c.OK)
    end)
    assert(unused:close() == c.OK and sink:close() == c.OK and root:close() == c.OK)
  end
  for _, recipients in ipairs({false, true}) do
    local name = recipients and 'cose_encrypt' or 'cose_encrypt0'
    local kind = recipients and c.COSE_A256KW or c.COSE_A256GCM
    for _, suffix in ipairs({'_init', '_open', ''}) do
      for target=1,(recipients and 5 or 4) do
        local root = c.create({allocator=counting_allocator})
        local source, sink = native_case(1, false)
        -- Independent keys allow the options callback to close the runtime too.
        local keys = {c.cose_key_create(kind, string.rep('k',32)),
                      c.cose_key_create(kind, string.rep('l',32))}
        local arguments = {source, sink, root, keys[1], keys[2]}
        local key = recipients and {keys[1], keys[2]} or keys[1]
        closes_argument(function(options)
          return root[name..suffix](root, source, sink, key, options)
        end, function()
          assert(arguments[target]:close() == c.OK)
          if recipients and target >= 4 then
            key[target-3] = keys[6-target]
          end
        end)
        assert(source:close() == c.OK and sink:close() == c.OK)
        assert(keys[1]:close() == c.OK and keys[2]:close() == c.OK and root:close() == c.OK)
      end
      local root = c.create({allocator=counting_allocator})
      local source, sink = native_case(1, false)
      local key = c.cose_key_create(kind, string.rep('k',32))
      rejects_bad_options(function(options)
        return root[name..suffix](root, source, sink, recipients and {key} or key, options)
      end)
      assert(source:close() == c.OK and sink:close() == c.OK)
      assert(key:close() == c.OK and root:close() == c.OK)
    end
  end
  for target=1,2 do
    local root = c.create({allocator=counting_allocator})
    local source, sink = native_case(1, false)
    local unused, replacement = native_case(2, false)
    local key = root:cose_key_init(c.COSE_A256GCM, string.rep('k',32))
    local op = root:cose_encrypt0_init(source, sink, key)
    closes_argument(function(options) return op:next(replacement, options) end,
                    function() assert((target == 1 and op or replacement):close() == c.OK) end)
    assert(op:close() == c.OK and replacement:close() == c.OK)
    assert(source:close() == c.OK and sink:close() == c.OK and unused:close() == c.OK)
    assert(key:close() == c.OK and root:close() == c.OK)
  end
  for _, name in ipairs({'cwt_init', 'cwt_create'}) do
    local root = c.create({allocator=counting_allocator})
    closes_argument(function(options) return root[name](root, options) end,
                    function() assert(root:close() == c.OK) end)
  end
  for target=1,2 do
    local root = c.create({allocator=counting_allocator})
    local token = root:cwt_create()
    local bytes = c.span('invalid token')
    closes_argument(function(policy) return token:verify(bytes, policy) end,
                    function() assert((target == 1 and token or bytes):close() == c.OK) end,
                    {now=100}, target == 2 and 'string expected' or nil)
    assert(token:close() == c.OK and bytes:close() == c.OK and root:close() == c.OK)
  end
end
for _, name in ipairs({'json_to_cbor', 'cbor_to_json', 'encode_map', 'decode_map'}) do
  local mode = name == 'json_to_cbor' and 1 or name == 'cbor_to_json' and 2 or name == 'encode_map' and 3 or 4
  local first, second = native_case(mode)
  local lookups = 0
  local options = setmetatable({chunk=1, step_events=2}, {__index=function() lookups=lookups+1 end})
  local operation, status, diagnostic = runtime[name .. '_init'](runtime, first, second, options)
  assert(lookups > 0)
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
for _, drain in ipairs({'advance', 'read'}) do
  local encoder = c.encoder()
  local owner = c.span(string.rep('x', 1000))
  local token = c.token(c.DATA, 0, owner)
  assert(encoder:put(c.token(c.BYTES, 1000)) == c.OK)
  assert(encoder:read() == c.OK)
  assert(encoder:put(token) == c.OK)
  local status, first = encoder:peek()
  assert(status == c.OUTPUT and first:length() == 1000)
  assert(encoder:advance(400) == c.OUTPUT)
  local status, second = encoder:peek()
  assert(status == c.OUTPUT and second:length() == 600)
  assert(encoder[drain](encoder, 600) == c.OK)
  assert(token:close() == c.INVALID and owner:close() == c.INVALID)
  assert(first:string() == string.rep('x', 1000))
  assert(first:close() == c.OK and token:close() == c.INVALID)
  -- Only the outstanding peek now retains the token and its string owner.
  token, owner = nil, nil
  collectgarbage('collect')
  collectgarbage('collect')
  assert(second:string() == string.rep('x', 600))
  assert(encoder:reset() == c.BUSY)
  assert(second:close() == c.OK)
  assert(encoder:put(c.token(c.END, c.BYTES)) == c.OK)
  assert(encoder:finish() == c.OK)
  assert(encoder:reset() == c.OK and encoder:close() == c.OK)
end
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
-- Sign1/Mac0 use the same native flow, including all constructor modes.
do
  local root = c.create({allocator=counting_allocator})
  local raw = string.rep('\0',31)..'\1'
  for _, kind in ipairs({c.COSE_ED25519_PRIVATE, c.COSE_P256_PRIVATE, c.COSE_HMAC256}) do
    local key = assert(root:cose_key_create(kind, raw))
    local verify_key = key
    if kind ~= c.COSE_HMAC256 then
      local status, public = key:public_key()
      assert(status == c.OK and #public == (kind == c.COSE_P256_PRIVATE and 65 or 32))
      verify_key = assert(root:cose_key_init(kind == c.COSE_P256_PRIVATE and c.COSE_P256_PUBLIC or c.COSE_ED25519_PUBLIC, public))
    end
    for _, stream in ipairs({false,true}) do
      local seal = kind == c.COSE_HMAC256 and 'cose_mac0' or 'cose_sign1'
      local verify = kind == c.COSE_HMAC256 and 'cose_verify_mac0' or 'cose_verify1'
      if stream then seal=seal..'_stream'; verify=verify..'_stream' end
      for _, mode in ipairs({'','_init','_open'}) do
        local source, sink = native_case(1, mode ~= '')
        local lookups = 0
        local options = setmetatable({record_bytes=stream and 16 or 2048, aad='context'},
                                     {__index=function() lookups=lookups+1 end})
        if mode == '' then assert(root[seal](root,source,sink,key,options) == c.OK)
        else
          local op = assert(root[seal..mode](root,source,sink,key,options))
          assert(key:close() == c.INVALID)
          repeat local status,err=op:run(); assert(status>=0,err.message) until status==c.DONE
          assert(op:close()==c.OK)
        end
        assert(lookups > 0)
        assert(source:close()==c.OK and sink:close()==c.OK)
        source,sink = native_case(2, mode ~= '')
        if mode == '' then assert(root[verify](root,source,sink,verify_key,options)==c.OK)
        else
          local op = assert(root[verify..mode](root,source,sink,verify_key,options))
          repeat local status,err=op:run(); assert(status>=0,err.message) until status==c.DONE
          if stream then
            local status,info=op:stream_info()
            assert(status==c.OK and info.tag==(kind==c.COSE_HMAC256 and 17 or 18))
            assert(info.algorithm==(kind==c.COSE_HMAC256 and 5 or kind==c.COSE_P256_PRIVATE and -9 or -19))
          end
          assert(op:close()==c.OK)
        end
        assert(source:close()==c.OK and sink:close()==c.OK)
      end
    end
    if verify_key~=key then assert(verify_key:close()==c.OK) end
    assert(key:close()==c.OK)
  end
  assert(root:close()==c.OK)
end

-- Tokens are explicitly bounded. Native claims and policies cross as pointers;
-- Lua strings/tables are convenience surfaces for callers that want copies.
do
  local root=c.create({allocator=counting_allocator})
  assert(root:default_cwt_options().claims==64)
  local native_claims,native_policy=native_cwt_case()
  local policy={accepted_algs={'Ed25519','ES256','HS256'}, accepted_issuers={'issuer'},
                accepted_audiences={'service'}, required_claims={'sub','exp'}, now=100}
  local raw=string.rep('\0',31)..'\1'
  local content=root:cose_key_init(c.COSE_A256GCM,raw)
  local wrapping=root:cose_key_init(c.COSE_A256KW,raw)
  for _,kind in ipairs({c.COSE_ED25519_PRIVATE,c.COSE_P256_PRIVATE,c.COSE_HMAC256}) do
    local key=root:cose_key_init(kind,raw)
    for _,encrypt in ipairs({false,true}) do
      for _,ctor in ipairs({'cwt_init','cwt_create'}) do
        local token=assert(root[ctor](root,{require_cti=true,cose={encrypt=encrypt}}))
        assert(token:view_get()==c.INPUT)
        assert(token:set_lonejson(native_claims,'\0id')==c.OK)
        assert(not pcall(function() token:seal(-1) end))
        local status,view=token:view_get()
        assert(status==c.OK and not view.authenticated and view.cti=='\0id')
        assert(token:set_claims(view.encoded)==c.OK)
        local rc,issuer=token:claim(1)
        assert(rc==c.OK and issuer=='\x66issuer')
        assert(token:claim('absent')==c.INPUT)
        for _,encrypted in ipairs({false,true}) do
          local enc_key=encrypt and wrapping or content
          local recipients=encrypted and {enc_key} or nil
          assert(token:set_seal_keys(key,recipients)==c.OK)
          if recipients then recipients[1]=nil end -- binding owns its snapshot
          assert(key:close()==c.INVALID) -- borrowed Lua handles cannot close
          local result,wire,err=token:seal()
          assert(result==c.OK,err.message)
          assert(wire:length()>0 and wire:string():sub(1,2)=='\xd8\x3d')
          assert(token:seal(1)==c.LIMIT)
          assert(token:set_verify_keys(key,encrypted and enc_key or nil)==c.OK)
          assert(token:verify(wire,native_policy)==c.OK)
          local why,verified=token:view_get()
          assert(why==c.OK and verified.authenticated and verified.claims.iss=='issuer')
          assert(token:verify(wire,policy)==c.OK)
          policy.now=1000
          assert(token:verify(wire,policy)==c.AUTH)
          assert(token:view_get()==c.INPUT)
          policy.now=100
          assert(token:set_lonejson(native_claims,'\0id')==c.OK)
          assert(wire:close()==c.OK)
        end
        assert(token:close()==c.OK)
      end
    end
    assert(key:close()==c.OK)
  end
  assert(native_claims:close()==c.OK and native_policy:close()==c.OK)
  assert(content:close()==c.OK and wrapping:close()==c.OK and root:close()==c.OK)
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

-- Public datagram constructors, ownership and native endpoints.
do
  local root=c.init()
  for _,ctor in ipairs({'datagram_init','datagram_create'}) do
    local a=assert(root[ctor](root,datagram_fd_a,32))
    local b=assert(c[ctor](root,datagram_fd_b,32))
    assert(b:receive()==c.INPUT)
    local rc,source=b:source()
    assert(rc==c.OK)
    local status,continuous=b:stream_source()
    assert(status==c.OK)
    local ok,sink=a:sink()
    assert(ok==c.OK)
    assert(a:send('\x81\x01')==c.OK)
    local got,message=b:receive()
    assert(got==c.OK and message.bytes:string()=='\x81\x01')
    assert(b:set_peer(message.peer)==c.OK)
    assert(a:send('\x00\x00')==c.MALFORMED)
    assert(b:reset()==c.OK)
    local _,counts=b:progress()
    assert(counts.received==1 and counts.input==2)
    local diagnostic,detail=b:diagnostic()
    assert(diagnostic==c.OK and detail.status==c.OK)
    assert(source:close()==c.OK and continuous:close()==c.OK and sink:close()==c.OK)
    assert(message.bytes:close()==c.OK)
    if message.peer then assert(message.peer:close()==c.OK) end
    assert(a:close()==c.OK and b:close()==c.OK)
  end
  assert(root:close()==c.OK)
end
