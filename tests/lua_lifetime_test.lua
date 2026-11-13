local c = require('cbor')
local group = assert(os.getenv('C89CBOR_LUA_LIFETIME_CASE'), 'missing lifetime test group')
local cases = 0
local function case(name, run)
  local ok, err = xpcall(run, debug.traceback)
  assert(ok, group..': '..name..': '..tostring(err))
  cases = cases + 1
end
local function finalized(allocator, observer)
  assert(observer:state().live == 0)
  assert(allocator:close() == c.OK)
  collectgarbage('collect')
  collectgarbage('collect')
  assert(observer:state().finalized == 1)
end
local guard = [[
  local c=require('cbor')
  assert(probe_allocator:close()==c.INVALID)
  if probe_root then assert(probe_root:close()==c.INVALID) end
  collectgarbage('collect')
  assert(probe_observer:state().finalized==0)
]]
if group == 'codec' then
  for _, name in ipairs({'encoder_create', 'decoder_create'}) do
    for _, rooted in ipairs({false, true}) do
      for _, failure in ipairs({'none', 'allocation', 'invalid allocator'}) do
        case(name..' rooted='..tostring(rooted)..' '..failure, function()
          local a, observer = native_allocator_case(failure == 'invalid allocator')
          local root = rooted and c.init() or nil
          probe_allocator, probe_observer, probe_root = a, observer, root
          observer:arm(guard, guard, failure == 'allocation' and 1 or 0)
          local codec, why
          if root then codec, why = root[name](root, a)
          else codec, why = c[name](a) end
          if failure ~= 'none' then
            assert(codec == nil and why == (failure == 'allocation' and c.NOMEM or c.INVALID))
          else
            assert(codec and a:close() == c.INVALID)
            if name == 'encoder_create' then
              local token = c.token(c.UINT, 1)
              assert(codec:put(token) == c.OK and token:close() == c.OK)
              local status, bytes = codec:read(8)
              assert(status == c.OK and bytes == '\1' and codec:finish() == c.OK)
            else
              local status, used, token = codec:next('\1')
              assert(status == c.TOKEN and used == 1 and token:argument() == 1)
              assert(token:close() == c.OK and codec:finish() == c.OK)
            end
            assert(codec:close() == c.OK)
            assert(observer:state().frees == 1)
          end
          assert(observer:state().calls == (failure == 'invalid allocator' and 0 or 1))
          if root then assert(root:close() == c.OK) end
          probe_allocator, probe_observer, probe_root = nil, nil, nil
          finalized(a, observer)
        end)
      end
    end
    for _, failure in ipairs({false, true}) do
      case(name..' inherits runtime allocator; fail='..tostring(failure), function()
        local a, observer = native_allocator_case()
        local root = c.init({allocator=a})
        probe_allocator, probe_observer, probe_root = a, observer, root
        observer:arm(guard, guard, failure and 1 or 0)
        local codec, why = root[name](root)
        if failure then assert(codec == nil and why == c.NOMEM)
        else assert(codec and codec:close() == c.OK) end
        assert(observer:state().calls == 1 and root:close() == c.OK)
        probe_allocator, probe_observer, probe_root = nil, nil, nil
        finalized(a, observer)
      end)
    end
    case(name..' rejects a closed allocator without allocation', function()
      local a, observer = native_allocator_case()
      finalized(a, observer)
      assert(not pcall(c[name], a))
      assert(observer:state().calls == 0)
    end)
  end
  for _, name in ipairs({'encoder', 'decoder'}) do
    for _, rooted in ipairs({false, true}) do
      case(name..' frame ownership and rejected reuse; rooted='..tostring(rooted), function()
        local root = rooted and c.init() or nil
        local frames = c.frames(2)
        local function construct()
          if root then return root[name](root, frames, 1) end
          return c[name](frames, 1)
        end
        local codec = assert(construct())
        assert(frames:close() == c.INVALID and not pcall(construct))
        assert(codec:close() == c.OK)
        codec = assert(construct())
        assert(codec:close() == c.OK and frames:close() == c.OK)
        assert(not pcall(construct))
        if root then assert(root:close() == c.OK) end
      end)
    end
  end
elseif group == 'runtime' then
  for _, ctor in ipairs({'init', 'create'}) do
    for _, replacement in ipairs({'nil', 'different', 'throw'}) do
      case(ctor..' allocator getter changes to '..replacement, function()
        local a, observer = native_allocator_case()
        local b = c.default_allocator()
        local reads = 0
        local config = setmetatable({}, {__index=function(_, key)
          if key == 'allocator' then
            reads = reads + 1
            if reads == 1 then return a end
            if replacement == 'throw' then error('allocator was read twice') end
            return replacement == 'different' and b or nil
          end
        end})
        local root = assert(c[ctor](config))
        assert(reads == 1 and a:close() == c.INVALID and b:close() == c.OK)
        -- Use and destroy a later allocation through the captured context.
        local child = assert(root:encoder_create())
        assert(child:close() == c.OK and root:close() == c.OK)
        finalized(a, observer)
      end)
    end
    case(ctor..' later configuration getter replaces allocator', function()
      local a, observer = native_allocator_case()
      local b = c.default_allocator()
      local config = setmetatable({allocator=a}, {__index=function(t, key)
        if key == 'json_config' then t.allocator=b; collectgarbage('collect') end
      end})
      local root = assert(c[ctor](config))
      assert(a:close() == c.INVALID and b:close() == c.OK)
      assert(root:close() == c.OK)
      finalized(a, observer)
    end)
    case(ctor..' later configuration getter closes allocator', function()
      local a, observer = native_allocator_case()
      local config = setmetatable({allocator=a}, {__index=function(_, key)
        if key == 'json_config' then
          assert(a:close() == c.OK)
          collectgarbage('collect')
        end
      end})
      assert(not pcall(c[ctor], config))
      assert(observer:state().finalized == 1 and observer:state().calls == 0)
    end)
    for _, bad in ipairs({'exception', 'type', 'invalid allocator'}) do
      case(ctor..' rejects '..bad..' without retaining allocator', function()
        local a, observer = native_allocator_case(bad == 'invalid allocator')
        local marker = {}
        local config = {allocator=a}
        if bad ~= 'invalid allocator' then
          config.json_config = setmetatable({}, {__index=function()
            if bad == 'exception' then error(marker, 0) end
            return 'not a size'
          end})
        end
        local ok, root, why = pcall(c[ctor], config)
        if bad == 'invalid allocator' then assert(ok and root == nil and why == c.INVALID)
        else assert(not ok and (bad ~= 'exception' or root == marker)) end
        finalized(a, observer)
      end)
    end
    for _, failure in ipairs({'none', 'invalid allocator', 'allocation'}) do
      if ctor == 'create' or failure ~= 'allocation' then
        case(ctor..' retains native configuration; '..failure, function()
          local a, observer = native_allocator_case(failure == 'invalid allocator')
          local config = native_config_case(a)
          probe_allocator, probe_observer, probe_config = a, observer, config
          local callback = guard..' assert(probe_config:close()==require("cbor").INVALID)'
          observer:arm(callback, callback, failure == 'allocation' and 1 or 0)
          local root, why = c[ctor](config)
          if failure == 'none' then
            assert(root and config:close() == c.INVALID)
            assert(root:close() == c.OK)
          else assert(root == nil and why == (failure == 'allocation' and c.NOMEM or c.INVALID)) end
          assert(config:close() == c.OK)
          probe_allocator, probe_observer, probe_config = nil, nil, nil
          finalized(a, observer)
        end)
      end
    end
  end
  for _, failure in ipairs({false, true}) do
    case('runtime allocation callback mutates config; fail='..tostring(failure), function()
      local a, observer = native_allocator_case()
      local b = c.default_allocator()
      probe_allocator, probe_observer, probe_replacement = a, observer, b
      probe_config = {allocator=a}
      observer:arm(guard..' probe_config.allocator=probe_replacement', guard, failure and 1 or 0)
      local root, why = c.create(probe_config)
      assert(b:close() == c.OK)
      if failure then assert(root == nil and why == c.NOMEM)
      else
        assert(root and a:close() == c.INVALID)
        local child = assert(root:decoder_create())
        assert(child:close() == c.OK and root:close() == c.OK)
      end
      probe_allocator, probe_observer, probe_replacement, probe_config = nil, nil, nil, nil
      finalized(a, observer)
    end)
  end
elseif group == 'policy' then
  local root = c.init()
  local key = root:cose_key_init(c.COSE_HMAC256, string.rep('k',32))
  local token = root:cwt_create()
  assert(token:set_claims('\xa3\x01\x61i\x03\x61a\x04\x19\x03\xe8') == c.OK)
  assert(token:set_seal_keys(key) == c.OK)
  local status, span = token:seal()
  assert(status == c.OK)
  local wire = span:string()
  assert(span:close() == c.OK and token:set_verify_keys(key) == c.OK)
  local names = {'accepted_algs','accepted_issuers','accepted_audiences',
                 'accepted_crit','required_scopes','required_claims'}
  local values = {{'HS256'},{'i'},{'a'},{'custom'},{'read'},{'iss'}}
  local function policy()
    return {now=100, accepted_algs={'HS256'}, accepted_issuers={'i'}, accepted_audiences={'a'}}
  end
  for i, name in ipairs(names) do
    for _, replacement in ipairs({'nil','number','different','throw'}) do
      case(name..' returns '..replacement..' on second lookup', function()
        local p = policy()
        p[name] = values[i]
        local expected = token:verify(wire, p)
        local reads = 0
        p[name] = nil
        setmetatable(p, {__index=function(_, field)
          if field ~= name then return end
          reads = reads + 1
          if reads == 1 then return values[i] end
          if replacement == 'throw' then error('policy array was read twice') end
          return replacement == 'number' and 42 or replacement == 'different' and {'changed'} or nil
        end})
        local ok, result = pcall(token.verify, token, wire, p)
        assert(ok and result == expected and reads == 1)
      end)
    end
    case(name..' is copied before later getters mutate its entries', function()
      local p, array = policy(), {table.unpack(values[i])}
      p[name] = array
      local expected = token:verify(wire, p)
      local later = names[i+1] or 'allowed_clock_skew'
      local saved = p[later]
      p[later] = nil
      setmetatable(p, {__index=function(_, field)
        if field == later then array[1]=false; collectgarbage('collect'); return saved end
      end})
      assert(token:verify(wire, p) == expected)
    end)
    for _, invalid in ipairs({'not a table', false, 7, {'bad\0entry'}, {false}, {{}}}) do
      case(name..' rejects invalid array or entry '..tostring(invalid), function()
        local p = policy()
        p[name] = invalid
        assert(not pcall(token.verify, token, wire, p))
        assert(token:verify(wire, policy()) == c.OK)
      end)
    end
    case(name..' getter exception remains a Lua error', function()
      local p, marker = policy(), {}
      p[name] = nil
      setmetatable(p, {__index=function(_, field) if field == name then error(marker,0) end end})
      local ok, err = pcall(token.verify, token, wire, p)
      assert(not ok and err == marker and token:verify(wire, policy()) == c.OK)
    end)
    for _, length in ipairs({0, 1, 3, 64}) do
      case(name..' snapshots '..length..' entries', function()
        local p, array = policy(), {}
        for j=1,length do array[j]=values[i][1] end
        p[name] = array
        local expected = token:verify(wire, p)
        local reads = 0
        p[name] = nil
        setmetatable(p, {__index=function(_, field)
          if field == name then reads=reads+1; return reads == 1 and array or {} end
        end})
        assert(token:verify(wire, p) == expected and reads == 1)
      end)
    end
    case(name..' nil is also read only once', function()
      local p, reads = policy(), 0
      p[name] = nil
      local expected = token:verify(wire, p)
      setmetatable(p, {__index=function(_, field)
        if field == name then reads=reads+1 end
      end})
      assert(token:verify(wire, p) == expected and reads == 1)
    end)
    case(name..' uses raw array access for sparse arrays', function()
      local p, marker = policy(), {}
      local array = {values[i][1], values[i][1], values[i][1]}
      array[2] = nil
      local length, sparse = rawlen(array), false
      for j=1,length do if rawget(array,j) == nil then sparse=true end end
      local expected
      if not sparse then
        p[name] = {table.unpack(array,1,length)}
        expected = token:verify(wire,p)
      end
      p[name] = setmetatable(array, {__index=function() error(marker,0) end,
                                   __len=function() error(marker,0) end})
      local ok, err = pcall(token.verify, token, wire, p)
      if sparse then assert(not ok and err ~= marker)
      else assert(ok and err == expected) end
      assert(token:verify(wire, policy()) == c.OK)
    end)
  end
  case('temporary policy strings survive mutation and collection', function()
    local p = policy()
    p.accepted_algs = {string.rep('unknown',64), 'HS256'}
    p.accepted_issuers = nil
    setmetatable(p, {__index=function(t, field)
      if field == 'accepted_issuers' then
        t.accepted_algs = nil
        collectgarbage('collect')
        return {'i'}
      end
    end})
    assert(token:verify(wire, p) == c.OK)
  end)
  case('now is read once', function()
    local p, reads = policy(), 0
    p.now = nil
    setmetatable(p, {__index=function(_, field)
      if field == 'now' then reads=reads+1; return reads == 1 and 100 or 10000 end
    end})
    assert(token:verify(wire, p) == c.OK and reads == 1)
  end)
  for _, field in ipairs({'now','allowed_clock_skew','expected_nonce','expected_azp'}) do
    case(field..' rejects invalid scalar and preserves token usability', function()
      local p = policy()
      p[field] = field:find('expected',1,true) and 'bad\0value' or false
      assert(not pcall(token.verify, token, wire, p))
      assert(token:verify(wire, policy()) == c.OK)
    end)
  end
  assert(token:close() == c.OK and key:close() == c.OK and root:close() == c.OK)
elseif group == 'gc' then
  collectgarbage('incremental')
  local pause = collectgarbage('param', 'pause', 0)
  local stepmul = collectgarbage('param', 'stepmul', 10000)
  local stepsize = collectgarbage('param', 'stepsize', 0)
  for _, method in ipairs({'source', 'sink'}) do
    for _, ctor in ipairs({'fd_create', 'fd'}) do
      for _, rooted in ipairs({false, true}) do
        for _, borrowed in ipairs({false, true}) do
          for _, pending in ipairs({1, 100}) do
            case(method..' '..ctor..' rooted='..tostring(rooted)..
                 ' borrowed='..tostring(borrowed)..' pending='..pending, function()
              collectgarbage('collect')
              local root = rooted and c.init() or nil
              local fd = root and root[ctor](root,0) or c[ctor](0)
              local construct = fd[method]
              local first = borrowed and construct(fd) or nil
              local active, inside, closed, blocked = false, 0, 0, 0
              collectgarbage('stop')
              for i=1,pending do
                setmetatable({}, {__gc=function()
                  if not active then return end
                  -- Assert the GC callback occurs in the native constructor,
                  -- rather than before the call or after it returns.
                  local constructing = false
                  for level=2,16 do
                    local info = debug.getinfo(level,'f')
                    if not info then break end
                    if info.func == construct then constructing=true; break end
                  end
                  if constructing then
                    inside = inside + 1
                    local status = fd:close()
                    if status == c.OK then closed=closed+1
                    elseif status == c.INVALID then blocked=blocked+1 end
                  end
                end})
              end
              collectgarbage('restart')
              active = true
              local ok, endpoint = pcall(construct,fd)
              active = false
              assert(inside > 0, 'GC did not run inside endpoint construction')
              assert(closed + blocked == inside, 'unexpected finalizer error or close status')
              if borrowed then
                assert(closed == 0 and ok and endpoint)
                assert(fd:close() == c.INVALID)
                assert(first:close() == c.OK and fd:close() == c.INVALID)
                assert(endpoint:close() == c.OK)
              else
                assert(closed > 0)
                assert(not ok and tostring(endpoint):find('handle is closed',1,true), tostring(endpoint))
              end
              assert(fd:close() == c.OK)
              if root then assert(root:close() == c.OK) end
              collectgarbage('collect')
            end)
          end
        end
      end
    end
  end
  collectgarbage('param', 'pause', pause)
  collectgarbage('param', 'stepmul', stepmul)
  collectgarbage('param', 'stepsize', stepsize)
else
  error('unknown lifetime group: '..group)
end
assert(cases > 0)
print('lifetime '..group..': '..cases..' cases passed')
local pump = c.transfer(native_source, native_sink, c.SEQUENCE)
assert(pump:run() == c.DONE and pump:close() == c.OK)
