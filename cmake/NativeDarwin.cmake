# Native diagnostics use the selected Xcode SDK and tools, without cross flags.
if(NOT CMAKE_HOST_SYSTEM_NAME STREQUAL "Darwin" OR
   NOT CMAKE_HOST_SYSTEM_PROCESSOR STREQUAL "arm64" OR
   NOT C89CBOR_TARGET STREQUAL "arm64-apple-darwin")
  message(FATAL_ERROR "Native Darwin checks require an Apple Silicon macOS host")
endif()
find_program(C89CBOR_XCRUN xcrun REQUIRED)
foreach(pair clang:CMAKE_C_COMPILER clang++:CMAKE_CXX_COMPILER ld:CMAKE_LINKER
    ar:CMAKE_AR ranlib:CMAKE_RANLIB strip:CMAKE_STRIP nm:CMAKE_NM
    otool:CMAKE_OTOOL install_name_tool:CMAKE_INSTALL_NAME_TOOL)
  string(REPLACE ":" ";" fields "${pair}")
  list(GET fields 0 tool)
  list(GET fields 1 variable)
  execute_process(COMMAND "${C89CBOR_XCRUN}" --sdk macosx --find "${tool}"
    OUTPUT_VARIABLE path OUTPUT_STRIP_TRAILING_WHITESPACE COMMAND_ERROR_IS_FATAL ANY)
  if(NOT IS_ABSOLUTE "${path}" OR NOT EXISTS "${path}")
    message(FATAL_ERROR "Selected Xcode tool is unavailable: ${tool}: ${path}")
  endif()
  set(${variable} "${path}" CACHE FILEPATH "Selected Xcode tool" FORCE)
endforeach()
execute_process(COMMAND "${C89CBOR_XCRUN}" --sdk macosx --show-sdk-path
  OUTPUT_VARIABLE sdk OUTPUT_STRIP_TRAILING_WHITESPACE COMMAND_ERROR_IS_FATAL ANY)
if(NOT IS_ABSOLUTE "${sdk}" OR NOT IS_DIRECTORY "${sdk}")
  message(FATAL_ERROR "Selected Xcode macOS SDK is unavailable: ${sdk}")
endif()
set(CMAKE_OSX_SYSROOT "${sdk}" CACHE PATH "Selected Xcode SDK" FORCE)
set(CMAKE_OSX_ARCHITECTURES arm64 CACHE STRING "Native diagnostic architecture" FORCE)
set(CMAKE_OSX_DEPLOYMENT_TARGET "15.0" CACHE STRING "macOS deployment baseline" FORCE)
