/*
 * Copyright (c) 2018, NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _soft_periph__h_
#define _soft_periph__h_

#include <kernel.h>

#define SOFT_PERIPH_ENTRY_SIZE	(16)
#define SOFT_PERIPH_MAX_DEVICES	(8)

enum soft_periph_type {
	SOFT_PERIPH_UART,
	SOFT_PERIPH_SPI,
	SOFT_PERIPH_TERMINATOR
};

enum soft_periph_uart_flags {
	UART_HAS_RX = 1,
	UART_HAS_TX = 2,
	/* 4, 8, 16... */
};

struct soft_periph_config_entry {
	union {
		char *raw[SOFT_PERIPH_ENTRY_SIZE];
		struct {
			u8_t type;
			u8_t flags;

			u8_t txport;
			u8_t txpin;
			u8_t rxport;
			u8_t rxpin;
			u16_t padding;
			u32_t baud;	/* 115200 */
			char format[4];	/* 8N1 - data bits, parity, stop bits */
		} uart;
		struct {
			u8_t type;
			u8_t flags;

			u8_t mosiport;
			u8_t mosipin;
			u8_t misoport;
			u8_t misopin;
			u8_t clkport;
			u8_t clkpin;
			u8_t csport;
			u8_t cspin;
			u16_t padding;
			u32_t speed;
		} spi;
	};
};

struct gpio_pin_cfg {
	const char * const device_name;
	const u32_t port;
	const u32_t pin;
	bool used;
};

struct gpio_pin_cfg *get_gpio_pin_cfg(u32_t port, u32_t pin);

#endif /* _soft_periph__h_ */
