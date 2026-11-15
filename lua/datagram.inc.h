/* Complete datagrams stay in native bounded buffers. Returned spans borrow the
 * receiver and expire at its next receive/reset/stream read, as in the C API.
 */
static int datagram_factory(lua_State *L, int create) {
  c89cbor *runtime = check_runtime(L, 1);
  int base = runtime != NULL, descriptor, status;
  size_t capacity;
  c89cbor_datagram *native = NULL;
  c89cbor_error error;
  handle *h;
  lua_Integer value = luaL_checkinteger(L, 1 + base);
  if (value < 0 || value > INT_MAX)
    return luaL_argerror(L, 1 + base, "invalid socket descriptor");
  descriptor = (int)value;
  capacity = size_arg(L, 2 + base, 0);
  h = new_handle(L, DATAGRAM, create ? 0 : sizeof(*native));
  if (base)
    pin(L, h, 1, 1);
  h->active = 1;
  if (create) {
    status =
        c89cbor_datagram_create(runtime, descriptor, capacity, &native, &error);
    h->ptr = native;
    h->heap_kind = 11;
  } else
    status =
        c89cbor_datagram_init(runtime, h->ptr, descriptor, capacity, &error);
  h->active = 0;
  if (status != 0) {
    (void)release_handle(h);
    lua_pushnil(L);
  }
  result(L, status);
  diagnostic_table(L, &error);
  return 3;
}
static int datagram_init(lua_State *L) { return datagram_factory(L, 0); }
static int datagram_create(lua_State *L) { return datagram_factory(L, 1); }
static int datagram_receive(lua_State *L) {
  handle *h = checked(L, 1, DATAGRAM);
  c89cbor_datagram_message packet;
  c89cbor_error error;
  int status;
  if (h->active)
    return result(L, C89CBOR_BUSY);
  h->active = 1;
  status = c89cbor_datagram_receive(h->ptr, &packet, &error);
  h->active = 0;
  result(L, status);
  if (status == 0) {
    lua_newtable(L);
    push_span(L, packet.bytes, packet.length, 1);
    lua_setfield(L, -2, "bytes");
    if (packet.peer != NULL) {
      push_span(L, packet.peer, packet.peer_length, 1);
      lua_setfield(L, -2, "peer");
    }
  } else
    lua_pushnil(L);
  diagnostic_table(L, &error);
  return 3;
}
static int datagram_send(lua_State *L) {
  handle *h = checked(L, 1, DATAGRAM);
  size_t length, peer_length;
  const void *bytes = input(L, 2, &length), *peer = input(L, 3, &peer_length);
  c89cbor_error error;
  int status;
  if (h->active)
    return result(L, C89CBOR_BUSY);
  h->active = 1;
  status =
      c89cbor_datagram_send(h->ptr, bytes, length, peer, peer_length, &error);
  h->active = 0;
  result(L, status);
  diagnostic_table(L, &error);
  return 2;
}
static int datagram_set_peer(lua_State *L) {
  size_t length;
  const void *bytes = input(L, 2, &length);
  return result(L, c89cbor_datagram_set_peer(checked(L, 1, DATAGRAM)->ptr,
                                             bytes, length));
}
static int datagram_endpoint(lua_State *L, int mode) {
  handle *owner = checked(L, 1, DATAGRAM), *h;
  int status;
  h = new_handle(L, mode == 2 ? SINK : SOURCE,
                 mode == 2 ? sizeof(c89cbor_sink) : sizeof(c89cbor_source));
  status = mode == 2   ? c89cbor_datagram_sink(owner->ptr, h->ptr)
           : mode == 1 ? c89cbor_datagram_stream_source(owner->ptr, h->ptr)
                       : c89cbor_datagram_source(owner->ptr, h->ptr);
  if (status == 0)
    pin(L, h, 1, 1);
  else {
    (void)release_handle(h);
    lua_pushnil(L);
  }
  result(L, status);
  lua_insert(L, -2);
  return 2;
}
static int datagram_source(lua_State *L) { return datagram_endpoint(L, 0); }
static int datagram_stream_source(lua_State *L) {
  return datagram_endpoint(L, 1);
}
static int datagram_sink(lua_State *L) { return datagram_endpoint(L, 2); }
static int datagram_reset(lua_State *L) {
  return result(L, c89cbor_datagram_reset(checked(L, 1, DATAGRAM)->ptr));
}
static int datagram_progress(lua_State *L) {
  c89cbor_datagram_counts counts;
  int status = c89cbor_datagram_progress(checked(L, 1, DATAGRAM)->ptr, &counts);
  result(L, status);
  lua_newtable(L);
#define DATAGRAM_COUNT(field)                                                  \
  push_integer(L, counts.field);                                               \
  lua_setfield(L, -2, #field)
  DATAGRAM_COUNT(input);
  DATAGRAM_COUNT(output);
  DATAGRAM_COUNT(received);
  DATAGRAM_COUNT(sent);
  DATAGRAM_COUNT(rejected);
#undef DATAGRAM_COUNT
  return 2;
}
