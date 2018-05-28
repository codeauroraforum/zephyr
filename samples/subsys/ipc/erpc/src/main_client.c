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
#include "erpc_client_setup.h"
#include "erpc_error_handler.h"
#include "erpc_matrix_multiply.h"

#ifdef CPU_LPC54114J256BD64_cm4
#define ERPC_TRANSPORT_RPMSG_LITE_LINK_ID (RL_PLATFORM_LPC5411x_M4_M0_LINK_ID)
#else
#error Please define ERPC_TRANSPORT_RPMSG_LITE_LINK_ID for the CPU used.
#endif

#define MATRIX_ITEM_MAX_VALUE 50
#define APP_TASK_STACK_SIZE 640
K_THREAD_STACK_DEFINE(thread_stack, APP_TASK_STACK_SIZE);
static struct k_thread thread_data;

Matrix result_matrix = {0};

extern bool g_erpc_error_occurred;

/*!
 * @brief Fill matrices by random values
 */
static void fill_matrices(Matrix matrix1_ptr, Matrix matrix2_ptr)
{
	s32_t a;
	s32_t b;

	/* Fill both matrices by random values */
	for (a = 0; a < matrix_size; ++a) {
		for (b = 0; b < matrix_size; ++b) {
			matrix1_ptr[a][b] = rand() % MATRIX_ITEM_MAX_VALUE;
			matrix2_ptr[a][b] = rand() % MATRIX_ITEM_MAX_VALUE;
		}
	}
}

/*!
 * @brief Printing a matrix to the console
 */
static void print_matrix(Matrix matrix_ptr)
{
	s32_t a;
	s32_t b;

	for (a = 0; a < matrix_size; ++a) {
		for (b = 0; b < matrix_size; ++b) {
			printk("%4i ", (int)(matrix_ptr[a][b]));
		}
		printk("\r\n");
	}
}

void app_task(void *arg1, void *arg2, void *arg3)
{
	ARG_UNUSED(arg1);
	ARG_UNUSED(arg2);
	ARG_UNUSED(arg3);

	Matrix matrix1 = {0}, matrix2 = {0}, result_matrix = {0};

	printk("\r\nPrimary core started\r\n");

	/* RPMsg-Lite transport layer initialization */
	erpc_transport_t transport;

	env_sleep_msec(1000);

	transport = erpc_transport_rpmsg_lite_rtos_master_init(100, 101,
					ERPC_TRANSPORT_RPMSG_LITE_LINK_ID);

	/* MessageBufferFactory initialization */
	erpc_mbf_t message_buffer_factory;

	message_buffer_factory = erpc_mbf_rpmsg_init(transport);

	/* eRPC client side initialization */
	erpc_client_init(transport, message_buffer_factory);

	/* Set default error handler */
	erpc_client_set_error_handler(erpc_error_handler);

	/* Fill both matrices by random values */
	fill_matrices(matrix1, matrix2);

	/* Print both matrices on the console */
	printk("\r\nMatrix #1");
	printk("\r\n=========\r\n");
	print_matrix(matrix1);

	printk("\r\nMatrix #2");
	printk("\r\n=========\r\n");
	print_matrix(matrix2);

	while (1) {
		printk("\r\neRPC request is sent to the server\r\n");

		erpcMatrixMultiply(matrix1, matrix2, result_matrix);

		/* Check if some error occurred in eRPC */
		if (g_erpc_error_occurred) {
			/* Exit program loop */
			break;
		}

		printk("\r\nResult matrix");
		printk("\r\n=============\r\n");
		print_matrix(result_matrix);

		/* Wait 1s before another erpc request triggering
		 * (next matrix multiplication)
		 */
		env_sleep_msec(1000);

		/* Fill both matrices by random values */
		fill_matrices(matrix1, matrix2);

		/* Print both matrices on the console */
		printk("\r\nMatrix #1");
		printk("\r\n=========\r\n");
		print_matrix(matrix1);

		printk("\r\nMatrix #2");
		printk("\r\n=========\r\n");
		print_matrix(matrix2);
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
