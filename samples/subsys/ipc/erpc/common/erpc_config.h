/*
 * Copyright (c) 2018, NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * eRPC config values.
 * See $ZEPHYR_BASE/ext/multicore/erpc/erpc_c/config/erpc_config.h
 * for the list of all config items.
 */

#ifndef _ERPC_CONFIG_H_
#define _ERPC_CONFIG_H_

#define ERPC_THREADS_NONE (0)
#define ERPC_THREADS_PTHREADS (1)
#define ERPC_THREADS_FREERTOS (2)
#define ERPC_THREADS_ZEPHYR (3)

#define ERPC_NOEXCEPT_DISABLED (0)
#define ERPC_NOEXCEPT_ENABLED (1)

#define ERPC_NESTED_CALLS_DISABLED (0)
#define ERPC_NESTED_CALLS_ENABLED (1)

#define ERPC_NESTED_CALLS_DETECTION_DISABLED (0)
#define ERPC_NESTED_CALLS_DETECTION_ENABLED (1)

#define ERPC_MESSAGE_LOGGING_DISABLED (0)
#define ERPC_MESSAGE_LOGGING_ENABLED (1)

#define ERPC_THREADS (ERPC_THREADS_ZEPHYR)

#define ERPC_DEFAULT_BUFFER_SIZE (240)

#endif /* _ERPC_CONFIG_H_ */
