# Public API inventory

Generated from the public headers by CMake. Receiver twins share their
implementation. The API surface tests compare their function pointers in
installed static/shared consumers; Lua exports and native interop are checked
separately. Lua cleanup/destroy are aliases for close with Lua ownership rules.
Map methods accept a typed native record view. Binding methods are native C
embedding interfaces and do not move records through Lua tables.

| Export | C receiver or exception | Lua surface |
| --- | --- | --- |
| `c89cbor_cbor_to_json` | runtime.cbor_to_json | runtime:cbor_to_json |
| `c89cbor_cbor_to_json_init` | runtime.cbor_to_json_init | runtime:cbor_to_json_init |
| `c89cbor_cbor_to_json_open` | runtime.cbor_to_json_open | runtime:cbor_to_json_open |
| `c89cbor_cleanup` | runtime.cleanup | runtime:cleanup |
| `c89cbor_conversion_cleanup` | conversion.cleanup | conversion:cleanup |
| `c89cbor_conversion_destroy` | conversion.destroy | conversion:destroy |
| `c89cbor_conversion_diagnostic` | conversion.diagnostic | conversion:diagnostic |
| `c89cbor_conversion_progress` | conversion.progress | conversion:progress |
| `c89cbor_conversion_step` | conversion.step | conversion:step |
| `c89cbor_create` | Runtime bootstrap | cbor.create |
| `c89cbor_decode_map` | runtime.decode_map | runtime:decode_map |
| `c89cbor_decode_map_init` | runtime.decode_map_init | runtime:decode_map_init |
| `c89cbor_decode_map_open` | runtime.decode_map_open | runtime:decode_map_open |
| `c89cbor_decode_map_view` | runtime.decode_map_view | runtime:decode_map_view |
| `c89cbor_decode_map_view_init` | runtime.decode_map_view_init | runtime:decode_map_view_init |
| `c89cbor_decode_map_view_open` | runtime.decode_map_view_open | runtime:decode_map_view_open |
| `c89cbor_decoder_cleanup` | decoder.cleanup | decoder:cleanup |
| `c89cbor_decoder_create` | runtime.decoder_create | runtime:decoder_create |
| `c89cbor_decoder_destroy` | decoder.destroy | decoder:destroy |
| `c89cbor_decoder_diagnostic` | decoder.diagnostic | decoder:diagnostic |
| `c89cbor_decoder_finish` | decoder.finish | decoder:finish |
| `c89cbor_decoder_init` | runtime.decoder_init | runtime:decoder_init |
| `c89cbor_decoder_next` | decoder.next | decoder:next |
| `c89cbor_decoder_next_tag` | decoder.next_tag | decoder:next_tag |
| `c89cbor_decoder_reset` | decoder.reset | decoder:reset |
| `c89cbor_default_allocator` | Value helper; runtime.default_allocator twin | cbor.default_allocator |
| `c89cbor_default_config` | Value helper; runtime.default_config twin | cbor.default_config |
| `c89cbor_default_options` | Value helper; runtime.default_options twin | cbor.default_options |
| `c89cbor_destroy` | runtime.destroy | runtime:destroy |
| `c89cbor_diagnostic` | runtime.diagnostic | runtime:diagnostic |
| `c89cbor_encode_map` | runtime.encode_map | runtime:encode_map |
| `c89cbor_encode_map_init` | runtime.encode_map_init | runtime:encode_map_init |
| `c89cbor_encode_map_open` | runtime.encode_map_open | runtime:encode_map_open |
| `c89cbor_encode_map_view` | runtime.encode_map_view | runtime:encode_map_view |
| `c89cbor_encode_map_view_init` | runtime.encode_map_view_init | runtime:encode_map_view_init |
| `c89cbor_encode_map_view_open` | runtime.encode_map_view_open | runtime:encode_map_view_open |
| `c89cbor_encoder_advance` | encoder.advance | encoder:advance |
| `c89cbor_encoder_cleanup` | encoder.cleanup | encoder:cleanup |
| `c89cbor_encoder_create` | runtime.encoder_create | runtime:encoder_create |
| `c89cbor_encoder_destroy` | encoder.destroy | encoder:destroy |
| `c89cbor_encoder_diagnostic` | encoder.diagnostic | encoder:diagnostic |
| `c89cbor_encoder_end_tag` | encoder.end_tag | encoder:end_tag |
| `c89cbor_encoder_finish` | encoder.finish | encoder:finish |
| `c89cbor_encoder_init` | runtime.encoder_init | runtime:encoder_init |
| `c89cbor_encoder_peek` | encoder.peek | encoder:peek |
| `c89cbor_encoder_put` | encoder.put | encoder:put |
| `c89cbor_encoder_read` | encoder.read | encoder:read |
| `c89cbor_encoder_reset` | encoder.reset | encoder:reset |
| `c89cbor_encoder_tag` | encoder.tag | encoder:tag |
| `c89cbor_fd_cleanup` | fd.cleanup | fd:cleanup |
| `c89cbor_fd_create` | runtime.fd_create | runtime:fd_create |
| `c89cbor_fd_destroy` | fd.destroy | fd:destroy |
| `c89cbor_fd_diagnostic` | fd.diagnostic | fd:diagnostic |
| `c89cbor_fd_init` | runtime.fd_init | runtime:fd_init |
| `c89cbor_fd_sink` | fd.sink | fd:sink |
| `c89cbor_fd_source` | fd.source | fd:source |
| `c89cbor_float64_get` | runtime.float64_get | runtime:float64_get |
| `c89cbor_float64_set` | runtime.float64_set | runtime:float64_set |
| `c89cbor_init` | Runtime bootstrap | cbor.init |
| `c89cbor_json_to_cbor` | runtime.json_to_cbor | runtime:json_to_cbor |
| `c89cbor_json_to_cbor_init` | runtime.json_to_cbor_init | runtime:json_to_cbor_init |
| `c89cbor_json_to_cbor_open` | runtime.json_to_cbor_open | runtime:json_to_cbor_open |
| `c89cbor_length32` | runtime.length32 | runtime:length32 |
| `c89cbor_lua_check_allocator` | binding.check_allocator | Native binding.check_allocator |
| `c89cbor_lua_check_config` | binding.check_config | Native binding.check_config |
| `c89cbor_lua_check_conversion` | binding.check_conversion | Native binding.check_conversion |
| `c89cbor_lua_check_decoder` | binding.check_decoder | Native binding.check_decoder |
| `c89cbor_lua_check_encoder` | binding.check_encoder | Native binding.check_encoder |
| `c89cbor_lua_check_fd` | binding.check_fd | Native binding.check_fd |
| `c89cbor_lua_check_options` | binding.check_options | Native binding.check_options |
| `c89cbor_lua_check_reader` | binding.check_reader | Native binding.check_reader |
| `c89cbor_lua_check_record_view` | binding.check_record_view | Native binding.check_record_view |
| `c89cbor_lua_check_runtime` | binding.check_runtime | Native binding.check_runtime |
| `c89cbor_lua_check_sink` | binding.check_sink | Native binding.check_sink |
| `c89cbor_lua_check_source` | binding.check_source | Native binding.check_source |
| `c89cbor_lua_check_span` | binding.check_span | Native binding.check_span |
| `c89cbor_lua_check_transfer` | binding.check_transfer | Native binding.check_transfer |
| `c89cbor_lua_cleanup` | binding.cleanup | Native binding.cleanup |
| `c89cbor_lua_create` | Binding bootstrap | Native embedder |
| `c89cbor_lua_destroy` | binding.destroy | Native binding.destroy |
| `c89cbor_lua_diagnostic` | binding.diagnostic | Native binding.diagnostic |
| `c89cbor_lua_init` | Binding bootstrap | Native embedder |
| `c89cbor_lua_push_allocator` | binding.push_allocator | Native binding.push_allocator |
| `c89cbor_lua_push_config` | binding.push_config | Native binding.push_config |
| `c89cbor_lua_push_conversion` | binding.push_conversion | Native binding.push_conversion |
| `c89cbor_lua_push_decoder` | binding.push_decoder | Native binding.push_decoder |
| `c89cbor_lua_push_encoder` | binding.push_encoder | Native binding.push_encoder |
| `c89cbor_lua_push_fd` | binding.push_fd | Native binding.push_fd |
| `c89cbor_lua_push_options` | binding.push_options | Native binding.push_options |
| `c89cbor_lua_push_reader` | binding.push_reader | Native binding.push_reader |
| `c89cbor_lua_push_record_view` | binding.push_record_view | Native binding.push_record_view |
| `c89cbor_lua_push_runtime` | binding.push_runtime | Native binding.push_runtime |
| `c89cbor_lua_push_sink` | binding.push_sink | Native binding.push_sink |
| `c89cbor_lua_push_source` | binding.push_source | Native binding.push_source |
| `c89cbor_lua_push_span` | binding.push_span | Native binding.push_span |
| `c89cbor_lua_push_transfer` | binding.push_transfer | Native binding.push_transfer |
| `c89cbor_reader_cleanup` | reader.cleanup | reader:cleanup |
| `c89cbor_reader_create` | runtime.reader_create | runtime:reader_create |
| `c89cbor_reader_destroy` | reader.destroy | reader:destroy |
| `c89cbor_reader_diagnostic` | reader.diagnostic | reader:diagnostic |
| `c89cbor_reader_finish` | reader.finish | reader:finish |
| `c89cbor_reader_init` | runtime.reader_init | runtime:reader_init |
| `c89cbor_reader_next` | reader.next | reader:next |
| `c89cbor_reader_reset` | reader.reset | reader:reset |
| `c89cbor_runtime_default_allocator` | runtime.default_allocator | runtime:default_allocator |
| `c89cbor_runtime_default_config` | runtime.default_config | runtime:default_config |
| `c89cbor_runtime_default_options` | runtime.default_options | runtime:default_options |
| `c89cbor_status_string` | runtime.status_string | runtime:status_string |
| `c89cbor_transfer_cleanup` | transfer.cleanup | transfer:cleanup |
| `c89cbor_transfer_create` | runtime.transfer_create | runtime:transfer_create |
| `c89cbor_transfer_destroy` | transfer.destroy | transfer:destroy |
| `c89cbor_transfer_diagnostic` | transfer.diagnostic | transfer:diagnostic |
| `c89cbor_transfer_init` | runtime.transfer_init | runtime:transfer_init |
| `c89cbor_transfer_progress` | transfer.progress | transfer:progress |
| `c89cbor_transfer_step` | transfer.step | transfer:step |
| `c89cbor_version` | runtime.version | runtime:version |
| `luaopen_cbor` | Module opener bootstrap | require('cbor') |
