/*
 * Copyright (c) 2018 - 2019 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr.h>
#include <misc/printk.h>
#include <device.h>
#include <counter.h>
#include <string.h>
#include <gpio.h>
#include "soft_periph.h"
#include "clock_freq.h"
#include "rpmsg_lite.h"
#include "rpmsg_queue.h"
#include "rpmsg_ns.h"

/* Defines*/

#define GPIO_UART_PORT	GPIO_5_LABEL

#define MAX_BAUD_RATE	(115200U)
#define OVERSAMPLING	(4U)

#define TX_BUFFER_LEN	(32 * 10)
#define RX_BUFFER_LEN	(TX_BUFFER_LEN * 4 * 4)
#define TX_SIZE		((tx_wr + TX_BUFFER_LEN - tx_rd) % TX_BUFFER_LEN)
#define RX_SIZE		((rx_wr + RX_BUFFER_LEN - rx_rd) % RX_BUFFER_LEN)

#define RX_THREAD_STACK_SIZE	(500)
#define RX_THREAD_PRIORITY	(5)
#define TX_THREAD_STACK_SIZE	(500)
#define TX_THREAD_PRIORITY	(RX_THREAD_PRIORITY)

#define SOFT_PERIPH_ANNOUNCE_EP		(99)
#define SOFT_PERIPH_TXRX_EP_BASE	(100)

#ifdef CONFIG_SOC_SERIES_IMX_6X_M4
#define RPMSG_LITE_LINK_ID		(RL_PLATFORM_IMX6SX_M4_LINK_ID)
#define RPMSG_LITE_SHMEM_BASE		(0xBFFF0000)
#define RPMSG_LITE_NS_ANNOUNCE_STRING	"rpmsg-software-peripheral"
#else
#error Please define RPMSG_LITE_LINK_ID, RPMSG_LITE_SHMEM_BASE and \
RPMSG_LITE_NS_ANNOUNCE_STRING values for the CPU used.
#endif

/* Type definitions */

struct soft_uart_rx_context;
typedef int (*soft_uart_rx_state)(volatile struct soft_uart_rx_context *ctx,
				  u8_t sample);

struct soft_uart_rx_context {
	volatile u8_t pin;
	volatile u8_t last_sample;
	volatile u8_t accumulator;
	volatile u8_t result;
	volatile u16_t parity;
	volatile u8_t bit_number;
	volatile u8_t state;
	volatile u16_t divider;
	volatile u16_t div_counter;
	struct rpmsg_lite_endpoint *rpmsg_ept;

	volatile char *volatile char_buffer;
	volatile int char_buffer_length;
	unsigned long char_buffer_size;
	volatile u32_t data_timestamp;
	u32_t max_delay_before_send_ns;

	const soft_uart_rx_state *states;
};

struct soft_uart_tx_context;
typedef bool (*soft_uart_tx_state)(volatile struct soft_uart_tx_context *ctx,
				   volatile u32_t *port_value);

struct soft_uart_tx_context {
	volatile u8_t pin;

	volatile u8_t *volatile rpmsg_buffer;
	volatile u8_t *volatile data;
	volatile int length;
	volatile u8_t current;
	volatile u16_t parity;
	volatile u8_t bit_number;
	volatile u8_t state;
	volatile u16_t divider;
	volatile u16_t div_counter;
	volatile u32_t value;
	volatile rpmsg_queue_handle rpmsg_queue;
	const soft_uart_tx_state *states;
};

/* Variables */

static struct device *gpio_dev;
static struct rpmsg_lite_instance *volatile rpmsg;

/* Thread stacks and data */
K_THREAD_STACK_DEFINE(rx_thread_stack, RX_THREAD_STACK_SIZE);
K_THREAD_STACK_DEFINE(tx_thread_stack, TX_THREAD_STACK_SIZE);
static struct k_thread rx_thread_data;
static struct k_thread tx_thread_data;

/* TX ring buffer */
static volatile u32_t tx_buffer[TX_BUFFER_LEN];
static volatile u32_t tx_rd;
static volatile u32_t tx_wr;

/* RX ring buffer */
static volatile u32_t rx_buffer[RX_BUFFER_LEN];
static volatile u32_t rx_rd;
static volatile u32_t rx_wr;

/* Pin configurations */
static volatile struct soft_uart_rx_context
					   rx_contexts[SOFT_PERIPH_MAX_DEVICES];
static volatile struct soft_uart_tx_context
					   tx_contexts[SOFT_PERIPH_MAX_DEVICES];
static volatile int rx_count;
static volatile int tx_count;

/* TODO for debugging, remove: */
static volatile u32_t overflow_count;

/* Functions */

static inline int soft_uart_rx_state_should_fire(
				      volatile struct soft_uart_rx_context *ctx)
{
	ctx->div_counter--;

	if (ctx->div_counter == 0U) {
		ctx->div_counter = ctx->divider;
		return 1;
	}

	return 0;
}

static u8_t soft_uart_get_bit_from_samples(
				      volatile struct soft_uart_rx_context *ctx)
{
	if (ctx->accumulator < 2U) {
		/* Majority of zeroes */
		return 0U;
	}

	if (ctx->accumulator == 2U) {
		/* Same number of zeroes and ones - error */
		ctx->parity |= (1U << ctx->bit_number);
		return 0U;
	}

	/* Majority of ones */
	return 1U;
}

static int soft_uart_8N1_wait_for_start_bit(
				      volatile struct soft_uart_rx_context *ctx,
				      u8_t sample)
{
	if (!sample) {
		if (ctx->last_sample) {
			ctx->state++;
			ctx->bit_number = 0;
			ctx->result = 0;
			ctx->parity = 0;
		}
	}
	ctx->last_sample = sample;

	return -1;
}

static int soft_uart_8N1_sample_start_bit(
				      volatile struct soft_uart_rx_context *ctx,
				      u8_t sample)
{
	if (sample) {
		ctx->state = 0U;
	} else {
		ctx->state++;
	}

	ctx->last_sample = sample;

	return -1;
}

static int soft_uart_8N1_skip(volatile struct soft_uart_rx_context *ctx,
			      u8_t sample)
{
	ctx->state++;

	return -1;
}

static int soft_uart_8N1_first_sample(volatile struct soft_uart_rx_context *ctx,
				      u8_t sample)
{
	ctx->state++;
	/* Clear and set accumulator */
	ctx->accumulator = (sample != 0U);

	return -1;
}

static int soft_uart_8N1_sample(volatile struct soft_uart_rx_context *ctx,
				u8_t sample)
{
	ctx->state++;
	ctx->accumulator += (sample != 0U);

	return -1;
}

static int soft_uart_8N1_data_bit_last_sample(
				      volatile struct soft_uart_rx_context *ctx,
				      u8_t sample)
{
	/* Add last sample */
	ctx->accumulator += (sample != 0U);

	/* Decide by majority */
	if (soft_uart_get_bit_from_samples(ctx)) {
		ctx->result |= 0x80;
	}

	ctx->bit_number++;

	if (ctx->bit_number >= 8U) {
		ctx->state++;
	} else {
		ctx->result >>= 1;
		ctx->state -= 3;
	}

	return -1;
}

static int soft_uart_8N1_stop_bit_last_sample(
				      volatile struct soft_uart_rx_context *ctx,
				      u8_t sample)
{
	/* Add last sample */
	ctx->accumulator += (sample != 0U);

	ctx->last_sample = sample;
	ctx->state = 0U;

	if (soft_uart_get_bit_from_samples(ctx) && (ctx->parity == 0U)) {
		/* Stop bit detected and no error in this or previous bits */
		return ctx->result;
	}

	/* Bit error (in data bits or stop bit) */
	/* printk("s: %u, p: 0x%04x\n", sample, ctx->parity); */
	return -2;
}

static bool soft_uart_8N1_tx_idle(volatile struct soft_uart_tx_context *ctx,
				  volatile u32_t *port_value)
{
	if (ctx->length) {
		ctx->state++; /* start transmitting, if data available */
		return true;
	}

	*port_value |= (1U << ctx->pin);
	return false;
}

static bool soft_uart_8N1_tx_start_bit(
				      volatile struct soft_uart_tx_context *ctx,
				      volatile u32_t *port_value)
{
	ctx->state++;
	ctx->div_counter = ctx->divider;
	ctx->value = 0U; /* (0U << ctx->pin) */
	/* *port_value |= ctx->value; */

	ctx->bit_number = 0;
	ctx->parity = 0;

	ctx->current = *ctx->data++;
	ctx->length--;

	return false;
}

static bool soft_uart_8N1_tx_latch(volatile struct soft_uart_tx_context *ctx,
				   volatile u32_t *port_value)
{
	if (--ctx->div_counter != 0U) {
		*port_value |= ctx->value;
		return false;
	}

	ctx->state++;
	return true;
}

static bool soft_uart_8N1_tx_data_bit(volatile struct soft_uart_tx_context *ctx,
				      volatile u32_t *port_value)
{
	ctx->state++;
	ctx->div_counter = ctx->divider;
	ctx->value =
		   (((ctx->current & (1<<ctx->bit_number++)) != 0) << ctx->pin);
	*port_value |= ctx->value;

	return false;
}

static bool soft_uart_8N1_tx_decide(volatile struct soft_uart_tx_context *ctx,
				    volatile u32_t *port_value)
{
	if (ctx->bit_number >= 8)
		ctx->state++;
	else
		ctx->state -= 2U;

	return true;
}

static bool soft_uart_8N1_tx_stop_bit(volatile struct soft_uart_tx_context *ctx,
				      volatile u32_t *port_value)
{
	ctx->state++;
	ctx->div_counter = ctx->divider;
	ctx->value = (1U << ctx->pin);
	*port_value |= ctx->value;

	return false;
}

static bool soft_uart_8N1_tx_done(volatile struct soft_uart_tx_context *ctx,
				  volatile u32_t *port_value)
{
	if (ctx->length)
		ctx->state = 1U; /* start bit */
	else
		ctx->state = 0U; /* idle */

	return true;
}

/* State variables */

static const soft_uart_rx_state soft_uart_8N1_rx_states[] = {
	soft_uart_8N1_wait_for_start_bit,
	soft_uart_8N1_sample_start_bit, /* check first 3/4 of start bit is 0 */
	soft_uart_8N1_sample_start_bit,
	soft_uart_8N1_skip, /* end of start bit */

	soft_uart_8N1_first_sample, /* get data bit samples */
	soft_uart_8N1_sample,
	soft_uart_8N1_sample,
	soft_uart_8N1_data_bit_last_sample, /* decide by the majority */

	soft_uart_8N1_first_sample, /* get stop bit samples */
	soft_uart_8N1_sample,
	soft_uart_8N1_sample,
	soft_uart_8N1_stop_bit_last_sample, /* return the byte */
};

static const soft_uart_tx_state soft_uart_8N1_tx_states[] = {
	soft_uart_8N1_tx_idle,

	soft_uart_8N1_tx_start_bit,
	soft_uart_8N1_tx_latch,

	soft_uart_8N1_tx_data_bit,
	soft_uart_8N1_tx_latch,
	soft_uart_8N1_tx_decide, /* next bit or stop bit? */

	soft_uart_8N1_tx_stop_bit,
	soft_uart_8N1_tx_latch,
	soft_uart_8N1_tx_done, /* done transmitting a byte */
};

/* Functions */

static void counter_callback(struct device *dev, void *user_data)
{
	static u32_t divider = OVERSAMPLING;
	u32_t next_rx_wr;

	/* RX */
	if (rx_count > 0) {
		next_rx_wr = (rx_wr + 1U) % RX_BUFFER_LEN;

		if (next_rx_wr == rx_rd) {
			overflow_count++;
		} else {
			gpio_port_read(gpio_dev,
				       (u32_t *)&rx_buffer[next_rx_wr]);
			rx_wr = next_rx_wr;
		}
	}

	/* TX */
	if (tx_count > 0U) {
		divider--;
		if (divider == 0U) {
			divider = OVERSAMPLING;
			if (tx_rd == tx_wr) {
				/*
				 * tx buffer is empty - either there is
				 * nothing to send or it is underflow
				 */
				return;
			}

			gpio_port_write(gpio_dev, tx_buffer[tx_rd]);
			tx_rd = (tx_rd + 1U) % TX_BUFFER_LEN;
		}
	}
}

static void rx_check_timeout(volatile struct soft_uart_rx_context *rxctx)
{
	int ret;
	u64_t cycles;

	if (rxctx->char_buffer_length == 0U) {
		return;
	}

	cycles = k_cycle_get_32();
	if (cycles < rxctx->data_timestamp) {
		cycles += (((u64_t)1U) << 32);
	}

	if ((SYS_CLOCK_HW_CYCLES_TO_NS((u32_t)(cycles - rxctx->data_timestamp))
					      > rxctx->max_delay_before_send_ns)
	    || (rxctx->char_buffer_length == rxctx->char_buffer_size)) {
		do {
			ret = rpmsg_lite_send_nocopy(rpmsg, rxctx->rpmsg_ept,
						     rxctx->rpmsg_ept->addr,
						     (void *)rxctx->char_buffer,
						     rxctx->char_buffer_length);
		} while (ret != RL_SUCCESS);

		do {
			rxctx->char_buffer = rpmsg_lite_alloc_tx_buffer(rpmsg,
				      (unsigned long *)&rxctx->char_buffer_size,
				      RL_DONT_BLOCK);
		} while (rxctx->char_buffer == NULL);

		rxctx->char_buffer_length = 0;
	}
}

static void rx_check_timeouts(void)
{
	volatile struct soft_uart_rx_context *rxctx;
	int i;

	for (i = 0; i < rx_count; i++) {
		rxctx = &rx_contexts[i];
		rx_check_timeout(rxctx);
	}
}

static void rx_thread(void *p1, void *p2, void *p3)
{
	volatile struct soft_uart_rx_context *rxctx;
	/* u32_t cnt = 0U; */
	int i;
	int x;

	printk("%s starting\n", __func__);

	while (1) {
		if (rx_rd == rx_wr) {
			/* buffer empty */
			rx_check_timeouts();
			while (rx_rd == rx_wr)
				k_yield();
		}

		for (i = 0; i < rx_count; i++) {
			/* process each rx pin */
			rxctx = &rx_contexts[i];
			if (soft_uart_rx_state_should_fire(rxctx)) {
				x = rxctx->states[rxctx->state](rxctx,
			   ((rx_buffer[rx_rd] & (1U << rxctx->pin)) ? 1U : 0U));

				if (x >= 0) {
					/* printk("%d: %c <%02X>\n", i,x,x); */

					rxctx->char_buffer[
						rxctx->char_buffer_length++] =
									(char)x;
					if (rxctx->char_buffer_length == 1U) {
						rxctx->data_timestamp =
							       k_cycle_get_32();
					}

					rx_check_timeout(rxctx);
				} else if (x == -2) {
					/* TODO add error flag and send */
					/* printk("%d: Err\n", i); */
				}
			}
		}

		rx_rd = (rx_rd + 1U) % RX_BUFFER_LEN;

		/* TODO for debugging, remove: */
		/*
		 * cnt++;
		 * if ((cnt % 1500000U) == 0U) {
		 *         printk("overflow=%u\n", overflow_count);
		 *         printk("rx_size=%u\n", RX_SIZE);
		 *         printk("tx_size=%u\n", TX_SIZE);
		 * }
		 */
	}
}

static void tx_thread(void *p1, void *p2, void *p3)
{
	volatile struct soft_uart_tx_context *txctx;
	volatile u32_t *buffer;
	int i;
	u32_t idle_before;
	u32_t idle_after;
	u32_t next_tx_wr;

	printk("%s starting\n", __func__);

	gpio_port_write(gpio_dev, 0xFFFFFFFFU);

	while (1) {
		buffer = &tx_buffer[tx_wr];

		do {
			idle_before = 0U;
			idle_after = 0U;
			next_tx_wr = (tx_wr + 1U) % TX_BUFFER_LEN;

			while (next_tx_wr == tx_rd) {
				/* tx_buffer full */
				k_yield();
			}

			*buffer = 0U;

			for (i = 0; i < tx_count; i++) {
				/* process each tx pin */

				txctx = &tx_contexts[i];

				idle_before |= txctx->state;
				while (txctx->states[txctx->state](txctx,
								   buffer)) {
				}
				idle_after |= txctx->state;

				if (txctx->state == 0) {
					/* tx done, no tx in progress */
					if (txctx->rpmsg_buffer != NULL) {
						rpmsg_queue_nocopy_free(rpmsg,
						   (void *)txctx->rpmsg_buffer);
						txctx->rpmsg_buffer = NULL;
					}

					if (RL_SUCCESS  !=
						rpmsg_queue_recv_nocopy(rpmsg,
						txctx->rpmsg_queue, NULL,
						(char **)&(txctx->rpmsg_buffer),
						(int *)&(txctx->length), 0)) {
						txctx->length = 0;
						txctx->rpmsg_buffer = NULL;
					} else {
						txctx->data =
							    txctx->rpmsg_buffer;
					}
				}
			}

			if ((idle_before != 0U) || (idle_after != 0U)) {
				/*
				 * There was some activity, at least one tx pin
				 * did not begin and end in idle state.
				 * We can advance the buffer position. Otherwise
				 * tx_buffer would be filled needlessly.
				 */
				tx_wr = next_tx_wr;
				buffer = &tx_buffer[tx_wr];
			}

		/* while any tx state is not idle */
		} while (idle_after != 0U);

		k_yield();
	}
}

void main(void)
{
	u32_t val;
	u32_t base_baud_rate = 0U;
	int ret;
	int i;
	int len;
	int device_count;
	struct device *epit;
	volatile struct soft_uart_tx_context *txctx;
	volatile struct soft_uart_rx_context *rxctx;
	volatile rpmsg_queue_handle cfg_queue;
	struct rpmsg_lite_endpoint *volatile cfg_ept;
	volatile rpmsg_queue_handle rpmsg_queue;
	struct rpmsg_lite_endpoint *rpmsg_ept;
	struct gpio_pin_cfg *pin_cfg;
	k_tid_t tid;
	unsigned long src;
	char config_message[SOFT_PERIPH_ENTRY_SIZE * SOFT_PERIPH_MAX_DEVICES];
	struct soft_periph_config_entry cfg;

	printk("SW UART demo is starting...\n");

	gpio_dev = device_get_binding(GPIO_UART_PORT);

	if (!gpio_dev) {
		printk("device_get_binding(\"%s\") has failed\n",
			GPIO_UART_PORT);
		return;
	}

	/* Init RPMsg-Lite */
	rpmsg = rpmsg_lite_remote_init((void *)RPMSG_LITE_SHMEM_BASE,
				       RPMSG_LITE_LINK_ID, RL_NO_FLAGS);
	if (rpmsg == NULL) {
		printk("rpmsg is NULL\n");
		return;
	}

	while (!rpmsg_lite_is_link_up(rpmsg)) {
	}

	cfg_queue = rpmsg_queue_create(rpmsg);
	if (cfg_queue == NULL) {
		printk("cfg_queue is NULL\n");
		return;
	}

	cfg_ept = rpmsg_lite_create_ept(rpmsg, SOFT_PERIPH_ANNOUNCE_EP,
					rpmsg_queue_rx_cb, cfg_queue);
	if (cfg_ept == NULL) {
		printk("cfg_ept is NULL\n");
		return;
	}

	rpmsg_ns_announce(rpmsg, cfg_ept, RPMSG_LITE_NS_ANNOUNCE_STRING,
			  RL_NS_CREATE);

	/* Wait for initial configuration from LKM */
	printk("waiting for peripherals configuration... ");
	ret = rpmsg_queue_recv(rpmsg, cfg_queue, &src, config_message,
			       sizeof(config_message), &len, RL_BLOCK);
	if (ret != RL_SUCCESS) {
		printk("failed: %d\n", ret);
		return;
	}
	printk("ok, received it from endpoint %lu\n", src);
	if ((len == 0) || ((len % SOFT_PERIPH_ENTRY_SIZE) != 0)) {
		printk("invalid size of configuration message: %d\n", len);
		return;
	}
	device_count = len / SOFT_PERIPH_ENTRY_SIZE;
	printk("device_count = %d\n", device_count);

	/* Get base baud rate */
	for (i = 0; i < device_count; i++) {
		memcpy(cfg.raw,
		       config_message + (i * SOFT_PERIPH_ENTRY_SIZE),
		       SOFT_PERIPH_ENTRY_SIZE);

		if (cfg.uart.type != SOFT_PERIPH_UART) {
			printk("type not implemented: %u\n", cfg.uart.type);
			return;
		}

		if ((cfg.uart.baud == 0U) || (cfg.uart.baud > MAX_BAUD_RATE)) {
			printk("baud rate is out of range: %u", cfg.uart.baud);
			return;
		}

		if (cfg.uart.baud > base_baud_rate) {
			base_baud_rate = cfg.uart.baud;
		}
	}
	printk("base_baud_rate = %u\n", base_baud_rate);

	/* Initialize RX/TX contexts from received configuration */
	tx_count = 0;
	rx_count = 0;
	txctx = &tx_contexts[0];
	rxctx = &rx_contexts[0];
	for (i = 0; i < device_count; i++) {
		memcpy(cfg.raw,
		       config_message + (i * SOFT_PERIPH_ENTRY_SIZE),
		       SOFT_PERIPH_ENTRY_SIZE);

		printk("config item: type=%u, flags=%u, txport=%u, txpin=%u, "
			"rxport=%u, rxpin=%u, baud=%u, format=\"%s\"\n",
							cfg.uart.type,
							cfg.uart.flags,
							cfg.uart.txport,
							cfg.uart.txpin,
							cfg.uart.rxport,
							cfg.uart.rxpin,
							cfg.uart.baud,
							cfg.uart.format);

		if ((base_baud_rate % cfg.uart.baud) != 0) {
			printk("non divisible baud rates provided\n");
			return;
		}

		rpmsg_queue = rpmsg_queue_create(rpmsg);
		if (rpmsg_queue == NULL) {
			printk("rpmsg_queue is NULL\n");
			return;
		}

		rpmsg_ept = rpmsg_lite_create_ept(rpmsg,
						  SOFT_PERIPH_TXRX_EP_BASE + i,
						  rpmsg_queue_rx_cb,
						  rpmsg_queue);
		if (rpmsg_ept == NULL) {
			printk("rpmsg_ept is NULL\n");
			return;
		}

		if (cfg.uart.flags & UART_HAS_TX) {
			pin_cfg = get_gpio_pin_cfg(cfg.uart.txport,
						   cfg.uart.txpin);
			if ((pin_cfg == NULL) || (strcmp(GPIO_UART_PORT,
						  pin_cfg->device_name) != 0)) {
				printk("nonexisting or unsupported port.pin "
				    "%u.%u\n", cfg.uart.txport, cfg.uart.txpin);
				return;
			}

			if (pin_cfg->used) {
				printk("pin already used %u.%u\n",
					cfg.uart.txport, cfg.uart.txpin);
				return;
			}
			pin_cfg->used = true;

			txctx->pin = cfg.uart.txpin;
			txctx->divider = base_baud_rate / cfg.uart.baud;
			txctx->states = soft_uart_8N1_tx_states;
			txctx->state = 0U;
			txctx->data = NULL;
			txctx->length = 0;
			txctx->rpmsg_queue = rpmsg_queue;

			/* Setup GPIO output */

			ret = gpio_pin_configure(gpio_dev, txctx->pin,
						 GPIO_DIR_OUT);
			if (ret) {
				printk(
				  "configuring TX GPIO pin %u has failed: %d\n",
				  txctx->pin, ret);
				return;
			}

			ret = gpio_pin_read(gpio_dev, txctx->pin, &val);
			if (ret) {
				printk("reading pin %u has failed: %d\n",
					txctx->pin, ret);
				return;
			}

			txctx++;
			tx_count++;
		}

		if (cfg.uart.flags & UART_HAS_RX) {
			pin_cfg = get_gpio_pin_cfg(cfg.uart.rxport,
						   cfg.uart.rxpin);
			if ((pin_cfg == NULL) || (strcmp(GPIO_UART_PORT,
						  pin_cfg->device_name) != 0)) {
				printk("nonexisting or unsupported port.pin "
				    "%u.%u\n", cfg.uart.rxport, cfg.uart.rxpin);
				return;
			}

			if (pin_cfg->used) {
				printk("pin already used %u.%u\n",
					cfg.uart.rxport, cfg.uart.rxpin);
				return;
			}
			pin_cfg->used = true;

			rxctx->pin = cfg.uart.rxpin;
			rxctx->divider = base_baud_rate / cfg.uart.baud;
			rxctx->max_delay_before_send_ns = 1000000U; /* 1 ms */
			if ((10000000000 / cfg.uart.baud) >
					      rxctx->max_delay_before_send_ns) {
				/*
				 * If the number of nanoseconds needed to send
				 * one char is greater than the delay, send
				 * the received char immediately, do not wait
				 * for additional characters to form a group.
				 */
				rxctx->max_delay_before_send_ns = 0U;
			}

			rxctx->states = soft_uart_8N1_rx_states;
			rxctx->state = 0U;
			rxctx->div_counter = 1U;
			rxctx->rpmsg_ept = rpmsg_ept;

			/* Setup GPIO input */

			ret = gpio_pin_configure(gpio_dev, rxctx->pin,
						 GPIO_DIR_IN);
			if (ret) {
				printk(
				  "configuring RX GPIO pin %u has failed: %d\n",
				  rxctx->pin, ret);
				return;
			}

			ret = gpio_pin_read(gpio_dev, rxctx->pin, &val);
			if (ret) {
				printk("reading pin %u has failed: %d\n",
					rxctx->pin, ret);
				return;
			}

			/* Create buffer for sending of received data */

			rxctx->char_buffer_length = 0;
			rxctx->char_buffer = rpmsg_lite_alloc_tx_buffer(rpmsg,
				      (unsigned long *)&rxctx->char_buffer_size,
				      RL_DONT_BLOCK);
			if (rxctx->char_buffer == NULL) {
				printk("rx_contexts[%d].char_buffer is NULL\n",
					rx_count);
				return;
			}

			rxctx++;
			rx_count++;
		}
	}

	epit = device_get_binding(EPIT_1_LABEL);
	if (!epit) {
		printk("device_get_binding(EPIT) has failed\n");
		return;
	}

	ret = counter_start(epit);
	if (ret) {
		printk("counter_start has failed, %d\n", ret);
		return;
	}

	ret = counter_set_alarm(epit, counter_callback,
		(get_epit_clock_freq(EPIT1) / (base_baud_rate * OVERSAMPLING)) -
								      1U, NULL);
	if (ret) {
		printk("counter_set_alarm has failed, %d\n", ret);
		return;
	}

	/* Create and start RX/TX threads */

	if (tx_count > 0) {
		tid = k_thread_create(&tx_thread_data, tx_thread_stack,
				      TX_THREAD_STACK_SIZE, tx_thread,
				      NULL, NULL, NULL,
				      TX_THREAD_PRIORITY, K_ESSENTIAL,
				      K_NO_WAIT);
		if (tid == NULL) {
			printk("could not start tx_thread\n");
			return;
		}
	}

	if (rx_count > 0) {
		tid = k_thread_create(&rx_thread_data, rx_thread_stack,
				      RX_THREAD_STACK_SIZE, rx_thread,
				      NULL, NULL, NULL,
				      RX_THREAD_PRIORITY, K_ESSENTIAL,
				      K_NO_WAIT);
		if (tid == NULL) {
			printk("could not start rx_thread\n");
			return;
		}
	}
}
