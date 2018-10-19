/*
 * Copyright (c) 2018, NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include "soft_periph.h"

static struct gpio_pin_cfg gpios[] = {
#ifdef CONFIG_GPIO_IMX_PORT_6
	{.device_name = GPIO_6_LABEL, .port = 6U, .pin = 18U, .used = false},
	{.device_name = GPIO_6_LABEL, .port = 6U, .pin = 19U, .used = false},
#endif /* CONFIG_GPIO_IMX_PORT_6 */
#ifdef CONFIG_GPIO_IMX_PORT_4
	{.device_name = GPIO_4_LABEL, .port = 4U, .pin = 8U, .used = false},
#endif /* CONFIG_GPIO_IMX_PORT_4 */
#ifdef CONFIG_GPIO_IMX_PORT_5
	{.device_name = GPIO_5_LABEL, .port = 5U, .pin = 15U, .used = false},
	{.device_name = GPIO_5_LABEL, .port = 5U, .pin = 14U, .used = false},
	{.device_name = GPIO_5_LABEL, .port = 5U, .pin = 13U, .used = false},
	{.device_name = GPIO_5_LABEL, .port = 5U, .pin = 12U, .used = false},
	{.device_name = GPIO_5_LABEL, .port = 5U, .pin = 21U, .used = false},
#endif /* CONFIG_GPIO_IMX_PORT_5 */
#ifdef CONFIG_GPIO_IMX_PORT_4
	{.device_name = GPIO_4_LABEL, .port = 4U, .pin = 9U, .used = false},
#endif /* CONFIG_GPIO_IMX_PORT_4 */
#ifdef CONFIG_GPIO_IMX_PORT_5
	{.device_name = GPIO_5_LABEL, .port = 5U, .pin = 20U, .used = false},
	{.device_name = GPIO_5_LABEL, .port = 5U, .pin = 18U, .used = false},
	{.device_name = GPIO_5_LABEL, .port = 5U, .pin = 19U, .used = false},
#endif /* CONFIG_GPIO_IMX_PORT_5 */
#ifdef CONFIG_GPIO_IMX_PORT_4
	{.device_name = GPIO_4_LABEL, .port = 4U, .pin = 4U, .used = false},
	{.device_name = GPIO_4_LABEL, .port = 4U, .pin = 6U, .used = false},
#endif /* CONFIG_GPIO_IMX_PORT_4 */
};

struct gpio_pin_cfg *get_gpio_pin_cfg(u32_t port, u32_t pin)
{
	int i;
	struct gpio_pin_cfg *gpio;

	for (i = 0; i < ARRAY_SIZE(gpios); i++) {
		gpio = &gpios[i];
		if ((port == gpio->port) && (pin == gpio->pin)) {
			return gpio;
		}
	}

	return NULL;
}
