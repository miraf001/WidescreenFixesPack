cmake_minimum_required(VERSION 3.25)

project(FocusedResidentEvilFusionFixes LANGUAGES C CXX RC)

if(NOT WIN32)
    message(FATAL_ERROR "These ASI plugins can only be built for Windows.")
endif()

if(NOT MSVC)
    message(FATAL_ERROR "The focused build currently requires the MSVC-compatible toolchain.")
endif()

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
    message(FATAL_ERROR "Resident Evil Revelations 2 FusionFix must be built as a 32-bit binary.")
endif()

set(FOCUSED_MSVC_STL_INCLUDE "" CACHE PATH
    "Optional clean MSVC STL include directory placed before the installed toolset headers"
)
set(FOCUSED_EXPECTED_INCLUDE "" CACHE PATH
    "Optional tl::expected include directory for pre-C++23 MSVC toolsets"
)

set(FIX_PROJECT_NAME "ResidentEvilRevelations2.FusionFix")

set(FIX_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/source/${FIX_PROJECT_NAME}")
set(FIX_DATA_DIR "${CMAKE_CURRENT_SOURCE_DIR}/data/${FIX_PROJECT_NAME}")

if(NOT EXISTS "${FIX_SOURCE_DIR}/dllmain.cpp")
    message(FATAL_ERROR "Missing plugin source: ${FIX_SOURCE_DIR}/dllmain.cpp")
endif()

if(NOT DEFINED FOCUSED_PACKAGE_DIR OR FOCUSED_PACKAGE_DIR STREQUAL "")
    set(FOCUSED_PACKAGE_DIR "${CMAKE_BINARY_DIR}/package")
endif()
cmake_path(ABSOLUTE_PATH FOCUSED_PACKAGE_DIR NORMALIZE)

execute_process(
    COMMAND git rev-parse --short HEAD
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    OUTPUT_VARIABLE FIX_GIT_SHA
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
)
if(FIX_GIT_SHA STREQUAL "")
    set(FIX_GIT_SHA "unknown")
endif()

set(FIX_COMMON_SOURCES
    external/hooking/Hooking.Patterns.cpp
    external/injector/minhook/src/buffer.c
    external/injector/minhook/src/hde/hde32.c
    external/injector/minhook/src/hde/hde64.c
    external/injector/minhook/src/hook.c
    external/injector/minhook/src/trampoline.c
    external/injector/safetyhook/src/allocator.cpp
    external/injector/safetyhook/src/easy.cpp
    external/injector/safetyhook/src/inline_hook.cpp
    external/injector/safetyhook/src/mid_hook.cpp
    external/injector/safetyhook/src/os.windows.cpp
    external/injector/safetyhook/src/utility.cpp
    external/injector/safetyhook/src/vmt_hook.cpp
    external/injector/utility/FunctionHookMinHook.cpp
    external/injector/zydis/Zydis.c
    includes/stdafx.cpp
    Resources/VersionInfo.rc
)

add_library(${FIX_PROJECT_NAME} SHARED
    "${FIX_SOURCE_DIR}/dllmain.cpp"
    ${FIX_COMMON_SOURCES}
)

if(NOT FOCUSED_MSVC_STL_INCLUDE STREQUAL "")
    cmake_path(ABSOLUTE_PATH FOCUSED_MSVC_STL_INCLUDE NORMALIZE)
    if(NOT EXISTS "${FOCUSED_MSVC_STL_INCLUDE}/yvals_core.h"
       OR NOT EXISTS "${FOCUSED_MSVC_STL_INCLUDE}/xlocnum")
        message(FATAL_ERROR
            "FOCUSED_MSVC_STL_INCLUDE does not contain a complete MSVC STL header set: "
            "${FOCUSED_MSVC_STL_INCLUDE}"
        )
    endif()
    target_include_directories(${FIX_PROJECT_NAME} BEFORE PRIVATE
        "${FOCUSED_MSVC_STL_INCLUDE}"
    )
    message(STATUS "MSVC STL override: ${FOCUSED_MSVC_STL_INCLUDE}")
endif()

if(NOT FOCUSED_EXPECTED_INCLUDE STREQUAL "")
    if(FOCUSED_EXPECTED_INCLUDE STREQUAL ""
       OR NOT EXISTS "${FOCUSED_EXPECTED_INCLUDE}/tl/expected.hpp")
        message(FATAL_ERROR
            "MSVC ${MSVC_VERSION} requires the pinned tl::expected compatibility headers."
        )
    endif()
    target_include_directories(${FIX_PROJECT_NAME} BEFORE PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/tools/compat/msvc2019"
        "${FOCUSED_EXPECTED_INCLUDE}"
    )
    message(STATUS "C++23 expected compatibility: ${FOCUSED_EXPECTED_INCLUDE}")
elseif(MSVC_VERSION LESS 1930)
    message(FATAL_ERROR
        "MSVC ${MSVC_VERSION} requires the pinned tl::expected compatibility headers."
    )
endif()

target_include_directories(${FIX_PROJECT_NAME} PRIVATE
    external/injector/minhook/include
    external/injector/utility
    external/injector/safetyhook/include
    external/injector/zydis
    external/hooking
    external/injector/include
    external/inireader
    external/spdlog/include
    external/filewatch
    external/modutils
    includes
    includes/LED
    external/minidx9/Include
)

target_compile_definitions(${FIX_PROJECT_NAME} PRIVATE
    UNICODE
    _UNICODE
    $<$<CONFIG:Debug>:DEBUG>
    $<$<CONFIG:Debug>:_DEBUG>
    $<$<NOT:$<CONFIG:Debug>>:NDEBUG>
    "rsc_CompanyName=\"ThirteenAG / miraf001\""
    "rsc_LegalCopyright=\"MIT License\""
    "rsc_InternalName=\"${FIX_PROJECT_NAME}\""
    "rsc_ProductName=\"${FIX_PROJECT_NAME}\""
    "rsc_OriginalFilename=\"${FIX_PROJECT_NAME}.asi\""
    "rsc_FileDescription=\"Resident Evil Revelations 2 FusionFix\""
    "rsc_UpdateUrl=\"https://github.com/miraf001/WidescreenFixesPack\""
    rsc_FileVersion_MAJOR=0
    rsc_FileVersion_MINOR=1
    rsc_FileVersion_BUILD=2
    rsc_FileVersion_REVISION=0
    "rsc_FileVersion=\"0.1.2\""
    "rsc_ProductVersion=\"0.1.2-${FIX_GIT_SHA}\""
    "rsc_GitSHA1=\"${FIX_GIT_SHA}\""
    "rsc_GitSHA1W=L\"${FIX_GIT_SHA}\""
)

target_compile_options(${FIX_PROJECT_NAME} PRIVATE
    /utf-8
    /Zc:__cplusplus
    /W3
    $<$<COMPILE_LANGUAGE:CXX>:/std:c++latest>
)

set_property(TARGET ${FIX_PROJECT_NAME} PROPERTY
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
)

target_link_libraries(${FIX_PROJECT_NAME} PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/external/minidx9/Lib/x86/d3d9.lib"
    "${CMAKE_CURRENT_SOURCE_DIR}/external/minidx9/Lib/x86/d3dx9.lib"
    "${CMAKE_CURRENT_SOURCE_DIR}/includes/LED/LogitechLEDLib_x86.lib"
)

target_link_options(${FIX_PROJECT_NAME} PRIVATE
    $<$<NOT:$<CONFIG:Debug>>:/OPT:REF>
    $<$<NOT:$<CONFIG:Debug>>:/OPT:ICF>
)

set_target_properties(${FIX_PROJECT_NAME} PROPERTIES
    PREFIX ""
    SUFFIX ".asi"
    OUTPUT_NAME "${FIX_PROJECT_NAME}"
    RUNTIME_OUTPUT_DIRECTORY "${FOCUSED_PACKAGE_DIR}/scripts"
    LIBRARY_OUTPUT_DIRECTORY "${FOCUSED_PACKAGE_DIR}/scripts"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    PDB_OUTPUT_DIRECTORY "${FOCUSED_PACKAGE_DIR}/scripts"
)

set(FIX_INI "${FIX_DATA_DIR}/scripts/${FIX_PROJECT_NAME}.ini")
if(EXISTS "${FIX_INI}")
    add_custom_command(TARGET ${FIX_PROJECT_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${FIX_INI}"
            "${FOCUSED_PACKAGE_DIR}/scripts/${FIX_PROJECT_NAME}.ini"
        VERBATIM
    )
endif()

set(FIX_LOADER_MARKER "${FIX_DATA_DIR}/dinput8.ual")
if(EXISTS "${FIX_LOADER_MARKER}")
    add_custom_command(TARGET ${FIX_PROJECT_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${FIX_LOADER_MARKER}"
            "${FOCUSED_PACKAGE_DIR}/dinput8.ual"
        VERBATIM
    )
endif()

message(STATUS "Focused target: Resident Evil Revelations 2 (${FIX_PROJECT_NAME})")
message(STATUS "Package output: ${FOCUSED_PACKAGE_DIR}")
