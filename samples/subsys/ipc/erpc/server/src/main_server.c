/*
 * Copyright (c) 2018, NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr.h>
#include <misc/printk.h>
#include <device.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rpmsg_lite.h"
#include "erpc_server_setup.h"
#include "erpc_matrix_multiply_server.h"
#include "erpc_matrix_multiply.h"
#include "erpc_error_handler.h"

#ifdef CPU_LPC54114J256BD64_cm0plus
#define ERPC_TRANSPORT_RPMSG_LITE_LINK_ID (RL_PLATFORM_LPC5411x_M4_M0_LINK_ID)
#define RPMSG_LITE_SHMEM_BASE (0x20026800)
#else
#error Please define ERPC_TRANSPORT_RPMSG_LITE_LINK_ID and \
	RPMSG_LITE_SHMEM_BASE values for the CPU used.
#endif

#define APP_TASK_STACK_SIZE (1024)
K_THREAD_STACK_DEFINE(thread_stack, APP_TASK_STACK_SIZE);
static struct k_thread thread_data;

/*!
 * @brief erpcMatrixMultiply function implementation.
 *
 * This is the implementation of the erpcMatrixMultiply function
 * called by the primary core.
 *
 * @param matrix1 First matrix
 * @param matrix2 Second matrix
 * @param result_matrix Result matrix
 */
void erpcMatrixMultiply(Matrix matrix1, Matrix matrix2, Matrix result_matrix)
{
	s32_t i;
	s32_t j;
	s32_t k;

	/* Clear the result matrix */
	for (i = 0; i < matrix_size; ++i) {
		for (j = 0; j < matrix_size; ++j) {
			result_matrix[i][j] = 0;
		}
	}

	/* Multiply two matrices */
	for (i = 0; i < matrix_size; ++i) {
		for (j = 0; j < matrix_size; ++j) {
			for (k = 0; k < matrix_size; ++k) {
				result_matrix[i][j] +=
					matrix1[i][k] * matrix2[k][j];
			}
		}
	}
}

void app_task(void *arg1, void *arg2, void *arg3)
{
	ARG_UNUSED(arg1);
	ARG_UNUSED(arg2);
	ARG_UNUSED(arg3);

	/* RPMsg-Lite transport layer initialization */
	erpc_transport_t transport;

	transport = erpc_transport_rpmsg_lite_rtos_remote_init(
			101, 100, (void *)RPMSG_LITE_SHMEM_BASE,
			ERPC_TRANSPORT_RPMSG_LITE_LINK_ID, NULL, NULL);

	/* MessageBufferFactory initialization */
	erpc_mbf_t message_buffer_factory;

	message_buffer_factory = erpc_mbf_rpmsg_init(transport);

	/* eRPC server side initialization */
	erpc_server_init(transport, message_buffer_factory);

	/* adding the service to the server */
	erpc_add_service_to_server(create_MatrixMultiplyService_service());

	/* process message */
	erpc_status_t status = erpc_server_run();

	/* handle error status */
	if (status != kErpcStatus_Success) {
		/* print error description */
		erpc_error_handler(status);

		/* stop erpc server */
		erpc_server_stop();
	}

	while (1) {
	}
}

void main(void)
{
	printk("===== app started ========\n");

	k_thread_create(&thread_data, thread_stack, APP_TASK_STACK_SIZE,
			(k_thread_entry_t)app_task,
			NULL, NULL, NULL, K_PRIO_COOP(7), 0, 0);
}
