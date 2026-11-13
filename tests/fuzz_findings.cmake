# Check current and AFL-renamed finding directories without requiring AFL to
# rerun a saved crash. The corpus/results stay native AFL files and directories.
set(path "${ROOT}/${WORK}")
file(REMOVE_RECURSE "${path}")
file(MAKE_DIRECTORY "${path}/default/crashes" "${path}/default/hangs")
file(WRITE "${path}/default/crashes/README.txt" "AFL explanation\n")
execute_process(COMMAND bash scripts/hardening.sh findings "${WORK}"
  WORKING_DIRECTORY "${ROOT}" RESULT_VARIABLE result)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "Empty findings rejected")
endif()
foreach(directory crashes hangs crashes.2026-11-13-11:32:28 hangs.2026-11-13-11:32:28)
  file(MAKE_DIRECTORY "${path}/default/${directory}")
  file(WRITE "${path}/default/${directory}/id:000000,sig:11" "saved finding\n")
  execute_process(COMMAND bash scripts/hardening.sh findings "${WORK}"
    WORKING_DIRECTORY "${ROOT}" RESULT_VARIABLE result ERROR_VARIABLE error)
  if(NOT result EQUAL 1 OR NOT error MATCHES "saved crash or hang")
    message(FATAL_ERROR "Saved ${directory} finding not rejected: ${result}: ${error}")
  endif()
  file(REMOVE "${path}/default/${directory}/id:000000,sig:11")
endforeach()
file(REMOVE_RECURSE "${path}")
