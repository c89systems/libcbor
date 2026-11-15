local cbor = require('cbor')
local path = assert(os.getenv('C89CBOR_LUA_DOCS'))
local file = assert(io.open(path, 'r'))
local classes, current = {}, nil
for line in file:lines() do
  local name, base = line:match('^%-%-%-@class ([%w.]+):?%s*([%w.]*)')
  if name then
    assert(not classes[name], 'duplicate class: ' .. name)
    current = { fields = {}, base = base ~= '' and base or nil }
    classes[name] = current
  end
  if line:match('^%-%-%-@field ') then
    local field, signature, description = line:match('^%-%-%-@field ([%w_]+)%?? (.+) # (.+)$')
    assert(current and field and signature and description, 'incomplete declaration: ' .. line)
    assert(not current.fields[field], 'duplicate field: ' .. field)
    current.fields[field] = signature
  end
end
file:close()

local function fields(name)
  local class = assert(classes[name], 'undocumented class: ' .. name)
  local result = class.base and fields(class.base) or {}
  for field, signature in pairs(class.fields) do result[field] = signature end
  return result
end

local checked = 0
local function check(name, actual, methods)
  local declared = fields(name)
  for field, value in pairs(actual) do
    if not field:match('^__') then
      local signature = assert(declared[field], 'undocumented member: ' .. name .. '.' .. field)
      if type(value) == 'function' then
        assert(signature:match('^fun%('), 'missing function signature: ' .. field)
        assert(not methods or signature:match('^fun%(self: cbor%.'), 'missing receiver: ' .. field)
      else
        assert(type(value) == 'number' and signature == 'integer', 'constant type mismatch: ' .. field)
      end
      checked = checked + 1
    end
  end
  for field in pairs(declared) do
    assert(actual[field] ~= nil, 'documented member is absent: ' .. name .. '.' .. field)
  end
end

check('cbor.Module', cbor, false)
local registry = debug.getregistry()
local handles = {
  Runtime='runtime', Conversion='conversion', RecordView='record_view',
  OptionsHandle='options', ConfigHandle='config', CoseKey='cose_key',
  CoseOperation='cose_operation', CoseOptionsHandle='cose_options', Cwt='cwt',
  Datagram='datagram', CwtOptionsHandle='cwt_options', JwtClaims='jwt_claims',
  JwtPolicy='jwt_policy', Decoder='decoder', Encoder='encoder', Token='token',
  Span='span', Reader='reader', Fd='fd', Transfer='transfer', Source='source',
  Sink='sink', Allocator='allocator', Frames='frames'
}
for name, metatable in pairs(handles) do
  check('cbor.' .. name, assert(registry['c89cbor.' .. metatable]), true)
end

-- Defaults are observable table contracts, including their nested option tables.
for name, values in pairs({
  Config=cbor.default_config(), Options=cbor.default_options(),
  CoseOptions=cbor.default_cose_options(), CwtOptions=cbor.default_cwt_options()
}) do
  local declared = fields('cbor.' .. name)
  for field in pairs(values) do
    assert(declared[field], 'undocumented default field: ' .. name .. '.' .. field)
  end
end
assert(type(assert(loadfile(path))()) == 'table', 'editor declarations must be valid Lua')
print(('Lua editor declarations cover %d registered members'):format(checked))
