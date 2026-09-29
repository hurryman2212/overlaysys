set(PROJECT_SRCS
    callstack.c
    callstack.S
    callstack_prepare.c
    hook.c
    patch.c
    sig.c
    syscall.c)
find_path(LIBCAPSTONE_INCLUDE_DIR capstone/capstone.h REQUIRED)
find_library(LIBCAPSTONE_SHARED NAMES capstone REQUIRED)

if(NOT CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64)$")
  message(FATAL_ERROR "The current OverlaySys patcher supports x86-64 only")
endif()
set(PATCHER_SRCS
    patcher/patcher.c
    patcher/util.c
    patcher/x86/runtime.c
    patcher/x86/intercept_desc.c
    patcher/x86/patcher.c
    patcher/x86/disasm_wrapper.c
    patcher/x86/intercept_template.S
    patcher/x86/intercept_wrapper.S
    patcher/x86/util.S)

add_library(overlaysys-patcher OBJECT ${PATCHER_SRCS})
set_target_properties(overlaysys-patcher PROPERTIES POSITION_INDEPENDENT_CODE ON
                                                    C_VISIBILITY_PRESET hidden)
target_include_directories(overlaysys-patcher
                           PRIVATE "${LIBCAPSTONE_INCLUDE_DIR}")
target_compile_definitions(overlaysys-patcher PRIVATE _GNU_SOURCE)
target_compile_options(overlaysys-patcher
                       PRIVATE $<$<COMPILE_LANGUAGE:C>:${C_FLAGS_PROJECT}>)

# Declare project for this scope
project(lib${ROOT_PROJECT_NAME})

# Both variants use the same position-independent objects.
add_library(${PROJECT_NAME} OBJECT ${PROJECT_SRCS})
add_dependencies(${PROJECT_NAME} version-${ROOT_PROJECT_NAME})
set_target_properties(${PROJECT_NAME} PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_compile_options(${PROJECT_NAME}
                       PRIVATE $<$<COMPILE_LANGUAGE:C>:${C_FLAGS_PROJECT}>)
target_compile_options(${PROJECT_NAME}
                       PRIVATE $<$<COMPILE_LANGUAGE:CXX>:${CXX_FLAGS_PROJECT}>)
# Resolve project headers relative to the including file or include/.
target_include_directories(
  ${PROJECT_NAME} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../include"
                          "${CMAKE_CURRENT_BINARY_DIR}/..")
target_link_libraries(${PROJECT_NAME} PRIVATE overlaysys::_headers
                                              PkgConfig::LIBDW)

# Embed objects rather than exporting a private object-library dependency.
add_library(${PROJECT_NAME}.a STATIC $<TARGET_OBJECTS:${PROJECT_NAME}>
                                     $<TARGET_OBJECTS:overlaysys-patcher>)
add_library(${PROJECT_NAME}.so SHARED $<TARGET_OBJECTS:${PROJECT_NAME}>
                                      $<TARGET_OBJECTS:overlaysys-patcher>)
add_library(overlaysys::${PROJECT_NAME}.a ALIAS ${PROJECT_NAME}.a)
add_library(overlaysys::${PROJECT_NAME}.so ALIAS ${PROJECT_NAME}.so)
foreach(kind a so)
  set_target_properties(${PROJECT_NAME}.${kind}
                        PROPERTIES PREFIX "" OUTPUT_NAME ${PROJECT_NAME})
  target_include_directories(
    ${PROJECT_NAME}.${kind}
    INTERFACE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>
              $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
  target_link_libraries(${PROJECT_NAME}.${kind} INTERFACE overlaysys::_headers)
endforeach()

target_link_libraries(
  ${PROJECT_NAME}.a
  INTERFACE x86linuxextra::libx86linuxextra.a overlaysys::_libcapstone_static
            overlaysys::_libdw_static ${CMAKE_DL_LIBS} Threads::Threads)
target_link_options(${PROJECT_NAME}.a INTERFACE LINKER:-z,nodelete)

target_link_libraries(
  ${PROJECT_NAME}.so
  PRIVATE "${LIBCAPSTONE_SHARED}" x86linuxextra::libx86linuxextra.so
          PkgConfig::LIBDW ${CMAKE_DL_LIBS} Threads::Threads)
target_link_options(${PROJECT_NAME}.so PRIVATE LINKER:-z,nodelete)

install(
  TARGETS ${PROJECT_NAME}.a ${PROJECT_NAME}.so
  EXPORT overlaysysTargets
  ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
