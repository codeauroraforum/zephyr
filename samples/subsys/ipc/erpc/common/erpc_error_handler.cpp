/*
 * Copyright (c) 2018, NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "erpc_error_handler.h"
#include <misc/printk.h>

bool g_erpc_error_occurred = false;

void erpc_error_handler(erpc_status_t err)
{
	switch (err) {
	case kErpcStatus_Fail:
		printk("\r\nGeneric failure\r\n");
		break;

	case kErpcStatus_InvalidArgument:
		printk("\r\nArgument is an invalid value\r\n");
		break;

	case kErpcStatus_Timeout:
		printk("\r\nOperated timed out\r\n");
		break;

	case kErpcStatus_InvalidMessageVersion:
		printk("\r\nMessage header contains an unknown version\r\n");
		break;

	case kErpcStatus_ExpectedReply:
		printk("\r\nExpected a reply message but got another message "
		       "type\r\n");
		break;

	case kErpcStatus_CrcCheckFailed:
		printk("\r\nMessage is corrupted\r\n");
		break;

	case kErpcStatus_BufferOverrun:
		printk("\r\nAttempt to read or write past the end "
		       "of a buffer\r\n");
		break;

	case kErpcStatus_UnknownName:
		printk("\r\nCould not find host with given name\r\n");
		break;

	case kErpcStatus_ConnectionFailure:
		printk("\r\nFailed to connect to host\r\n");
		break;

	case kErpcStatus_ConnectionClosed:
		printk("\r\nConnected closed by peer\r\n");
		break;

	case kErpcStatus_MemoryError:
		printk("\r\nMemory allocation error\r\n");
		break;

	case kErpcStatus_ServerIsDown:
		printk("\r\nServer is stopped\r\n");
		break;

	case kErpcStatus_InitFailed:
		printk("\r\nTransport layer initialization failed\r\n");
		break;

	case kErpcStatus_ReceiveFailed:
		printk("\r\nFailed to receive data\r\n");
		break;

	case kErpcStatus_SendFailed:
		printk("\r\nFailed to send data.\r\n");
		break;

	/* no error occurred */
	case kErpcStatus_Success:
		return;

	/* unhandled error */
	default:
		printk("\r\nUnhandled error occurred\r\n");
		break;
	}

	/* error occurred */
	g_erpc_error_occurred = true;
}
