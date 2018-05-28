/*
 * Copyright (c) 2018, NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _EMBEDDED_RPC__ERROR_HANDLER_H_
#define _EMBEDDED_RPC__ERROR_HANDLER_H_

#include "erpc_common.h"

/*!
 * @addtogroup error_handler
 * @{
 * @file
 */

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * @name Error handler
 * @{
 */

/*!
 * @brief This function handles eRPC errors.
 *
 * This function prints a description of occurred error and sets bool variable
 * g_erpc_error_occurred which is used for determining if error occurred in user
 * application on client side.
 */
void erpc_error_handler(erpc_status_t err);

/* @} */

#ifdef __cplusplus
}
#endif

/*! @} */
#endif /* _EMBEDDED_RPC__ERROR_HANDLER_H_ */
