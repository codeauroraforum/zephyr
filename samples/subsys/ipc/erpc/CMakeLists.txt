cmake_minimum_required(VERSION 3.8.2)

set(BOARD lpcxpresso54114_m4)

include($ENV{ZEPHYR_BASE}/cmake/app/boilerplate.cmake NO_POLICY_SCOPE)
include(ExternalProject)

ExternalProject_Add(
  erpc_server
  SOURCE_DIR ${APPLICATION_SOURCE_DIR}/server
  INSTALL_COMMAND ""      # This particular build system has no install command
)

project(NONE)

add_dependencies(core_m0_inc_target erpc_server)

enable_language(C ASM)

target_include_directories(app PRIVATE $ENV{ZEPHYR_BASE}/samples/subsys/ipc/erpc/common)
target_include_directories(app PRIVATE $ENV{ZEPHYR_BASE}/samples/subsys/ipc/erpc/common/service)
target_include_directories(app PRIVATE $ENV{ZEPHYR_BASE}/drivers)
target_include_directories(app PRIVATE $ENV{ZEPHYR_BASE}/samples/subsys/ipc/erpc/src)
target_include_directories(app PRIVATE $ENV{ZEPHYR_BASE}/samples/subsys/ipc/erpc/server/build/zephyr)
if(CONFIG_SOC_SERIES_LPC54XXX)
target_include_directories(app PRIVATE $ENV{ZEPHYR_BASE}/ext/lib/ipc/rpmsg_lite/lib/include/platform/lpc5411x)
endif()

target_sources(app PRIVATE ../common/service/erpc_matrix_multiply_client.cpp)
target_sources(app PRIVATE ../common/erpc_error_handler.cpp)
target_sources(app PRIVATE src/main_client.c)
if(CONFIG_SOC_SERIES_LPC54XXX)
target_sources(app PRIVATE $ENV{ZEPHYR_BASE}/ext/lib/ipc/rpmsg_lite/lib/rpmsg_lite/porting/platform/lpc5411x/rpmsg_platform_zephyr_ipm.c)
endif()
