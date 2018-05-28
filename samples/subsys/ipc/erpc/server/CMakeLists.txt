cmake_minimum_required(VERSION 3.8.2)

set(BOARD lpcxpresso54114_m0)

include($ENV{ZEPHYR_BASE}/cmake/app/boilerplate.cmake NO_POLICY_SCOPE)
project(NONE)

target_include_directories(app PRIVATE $ENV{ZEPHYR_BASE}/samples/subsys/ipc/erpc/common)
target_include_directories(app PRIVATE $ENV{ZEPHYR_BASE}/samples/subsys/ipc/erpc/common/service)
target_include_directories(app PRIVATE $ENV{ZEPHYR_BASE}/drivers)
if(CONFIG_SOC_SERIES_LPC54XXX)
target_include_directories(app PRIVATE $ENV{ZEPHYR_BASE}/ext/lib/ipc/rpmsg_lite/lib/include/platform/lpc5411x)
endif()

target_sources(app PRIVATE src/main_server.c)
target_sources(app PRIVATE ../common/service/erpc_matrix_multiply_server.cpp)
target_sources(app PRIVATE ../common/erpc_error_handler.cpp)
if(CONFIG_SOC_SERIES_LPC54XXX)
target_sources(app PRIVATE $ENV{ZEPHYR_BASE}/ext/lib/ipc/rpmsg_lite/lib/rpmsg_lite/porting/platform/lpc5411x/rpmsg_platform_zephyr_ipm.c)
endif()
