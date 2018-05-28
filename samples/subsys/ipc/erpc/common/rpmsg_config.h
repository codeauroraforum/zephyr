/*
 * Copyright (c) 2018, NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _RPMSG_CONFIG_H
#define _RPMSG_CONFIG_H

#include "erpc_config_internal.h"

/*
 * RPMsg config values.
 * See $ZEPHYR_BASE/ext/multicore/rpmsg_lite/lib/include/rpmsg_default_config.h
 * for the list of all config items.
 */

#define RL_MS_PER_INTERVAL (1)

#define RL_BUFFER_PAYLOAD_SIZE (ERPC_DEFAULT_BUFFER_SIZE)

#define RL_BUFFER_COUNT (ERPC_DEFAULT_BUFFERS_COUNT)

#define RL_API_HAS_ZEROCOPY (1)

#define RL_USE_STATIC_API (0)

#define RL_ASSERT(x)			\
	do {				\
		if (!(x)) {		\
			while (1) {	\
			}		\
		}			\
	} while (0)

#endif /* _RPMSG_CONFIG_H */
