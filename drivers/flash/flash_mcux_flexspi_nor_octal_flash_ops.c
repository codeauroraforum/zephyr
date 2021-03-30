/*
 * Copyright 2020 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define DT_DRV_COMPAT	nxp_imx_flexspi_nor

#include <drivers/flash.h>
#include <logging/log.h>
#include <sys/util.h>
#include "spi_nor.h"
#include "flash_mcux_flexspi.h"

#ifdef CONFIG_HAS_MCUX_CACHE
#include <fsl_cache.h>
#endif

#define NOR_WRITE_SIZE	1
#define NOR_ERASE_VALUE	0xff

LOG_MODULE_DECLARE(flash_flexspi, CONFIG_FLASH_LOG_LEVEL);

struct flash_flexspi_nor_config {
	char *controller_label;
	flexspi_port_t port;
	flexspi_device_config_t config;
	struct flash_pages_layout layout;
	struct flash_parameters flash_parameters;
};

struct flash_flexspi_nor_data {
	const struct device *controller;
};

#define NOR_CMD_LUT_SEQ_IDX_READ            0
#define NOR_CMD_LUT_SEQ_IDX_READSTATUS      1
#define NOR_CMD_LUT_SEQ_IDX_WRITEENABLE     2
#define NOR_CMD_LUT_SEQ_IDX_READID_OPI      3
#define NOR_CMD_LUT_SEQ_IDX_WRITEENABLE_OPI 4
#define NOR_CMD_LUT_SEQ_IDX_ERASESECTOR     5
#define NOR_CMD_LUT_SEQ_IDX_CHIPERASE       6
#define NOR_CMD_LUT_SEQ_IDX_PAGEPROGRAM     7
#define NOR_CMD_LUT_SEQ_IDX_ENTEROPI        8
/* NOTE: Workaround for debugger.
   Must define AHB write FlexSPI sequence index to 9 to avoid debugger issue.
   Debugger can attach to the CM33 core only when ROM executes to certain place.
   At that point, AHB write FlexSPI sequence index is set to 9, but in LUT, the
   command is not filled by ROM. If the debugger sets software breakpoint at flash
   after reset/attachment, FlexSPI AHB write command will be triggered. It may
   cause AHB bus hang if the command in LUT sequence index 9 is any read opeartion.
   So we need to ensure at any time, the FlexSPI LUT sequence 9 for the flash must
   be set to STOP command to avoid unexpected debugger behaivor.
 */
#define NOR_CMD_LUT_SEQ_IDX_WRITE          9
#define NOR_CMD_LUT_SEQ_IDX_READSTATUS_OPI 10

#define CUSTOM_LUT_LENGTH        60

static int flash_flexspi_nor_get_vendor_id(const struct device *dev,
		uint8_t *vendor_id)
{
	const struct flash_flexspi_nor_config *config = dev->config;
	struct flash_flexspi_nor_data *data = dev->data;
	uint32_t buffer = 0;
	int ret;

	flexspi_transfer_t transfer = {
		.deviceAddress = 0,
		.port = config->port,
		.cmdType = kFLEXSPI_Read,
		.SeqNumber = 1,
		.seqIndex = NOR_CMD_LUT_SEQ_IDX_READID_OPI,
		.data = &buffer,
		.dataSize = 1,
	};

	LOG_DBG("Reading id");

	ret = flash_flexspi_transfer(data->controller, &transfer);
	*vendor_id = buffer;

	return ret;
}

static int flash_flexspi_nor_read_status(const struct device *dev,
		uint32_t *status)
{
	const struct flash_flexspi_nor_config *config = dev->config;
	struct flash_flexspi_nor_data *data = dev->data;

	flexspi_transfer_t transfer = {
		.deviceAddress = 0,
		.port = config->port,
		.cmdType = kFLEXSPI_Read,
		.SeqNumber = 1,
		.seqIndex = NOR_CMD_LUT_SEQ_IDX_READSTATUS_OPI,
		.data = status,
		.dataSize = 1,
	};

	LOG_DBG("Reading status register");

	return flash_flexspi_transfer(data->controller, &transfer);
}

static int flash_flexspi_nor_write_status(const struct device *dev,
		uint32_t *status)
{
	const struct flash_flexspi_nor_config *config = dev->config;
	struct flash_flexspi_nor_data *data = dev->data;

	flexspi_transfer_t transfer = {
		.deviceAddress = 0,
		.port = config->port,
		.cmdType = kFLEXSPI_Write,
		.SeqNumber = 1,
		.seqIndex = NOR_CMD_LUT_SEQ_IDX_ENTEROPI,
		.data = status,
		.dataSize = 1,
	};

	LOG_DBG("Writing status register");

	return flash_flexspi_transfer(data->controller, &transfer);
}

static int flash_flexspi_nor_write_enable(const struct device *dev, bool enableOctal)
{
	const struct flash_flexspi_nor_config *config = dev->config;
	struct flash_flexspi_nor_data *data = dev->data;
	
	flexspi_transfer_t transfer;
	
	transfer.deviceAddress = 0;
	transfer.port = config->port;
	transfer.cmdType = kFLEXSPI_Command;
	transfer.SeqNumber = 1;
	transfer.data = NULL;
	transfer.dataSize = 0;
	
	if (enableOctal)
	{
		transfer.seqIndex = NOR_CMD_LUT_SEQ_IDX_WRITEENABLE_OPI;
	}
	else
	{
		transfer.seqIndex = NOR_CMD_LUT_SEQ_IDX_WRITEENABLE;
	}
	LOG_DBG("Enabling write");

	return flash_flexspi_transfer(data->controller, &transfer);
}

static int flash_flexspi_nor_erase_sector(const struct device *dev,
	off_t offset)
{
	const struct flash_flexspi_nor_config *config = dev->config;
	struct flash_flexspi_nor_data *data = dev->data;

	flexspi_transfer_t transfer = {
		.deviceAddress = offset,
		.port = config->port,
		.cmdType = kFLEXSPI_Command,
		.SeqNumber = 1,
		.seqIndex = NOR_CMD_LUT_SEQ_IDX_ERASESECTOR,
		.data = NULL,
		.dataSize = 0,
	};

	LOG_DBG("Erasing sector at 0x%08x", offset);

	return flash_flexspi_transfer(data->controller, &transfer);
}

static int flash_flexspi_nor_erase_chip(const struct device *dev)
{
	const struct flash_flexspi_nor_config *config = dev->config;
	struct flash_flexspi_nor_data *data = dev->data;

	flexspi_transfer_t transfer = {
		.deviceAddress = 0,
		.port = config->port,
		.cmdType = kFLEXSPI_Command,
		.SeqNumber = 1,
		.seqIndex = NOR_CMD_LUT_SEQ_IDX_CHIPERASE,
		.data = NULL,
		.dataSize = 0,
	};

	LOG_DBG("Erasing chip");

	return flash_flexspi_transfer(data->controller, &transfer);
}

static int flash_flexspi_nor_page_program(const struct device *dev,
		off_t offset, const void *buffer, size_t len)
{
	const struct flash_flexspi_nor_config *config = dev->config;
	struct flash_flexspi_nor_data *data = dev->data;

	flexspi_transfer_t transfer = {
		.deviceAddress = offset,
		.port = config->port,
		.cmdType = kFLEXSPI_Write,
		.SeqNumber = 1,
		.seqIndex = NOR_CMD_LUT_SEQ_IDX_PAGEPROGRAM,
		.data = (uint32_t *) buffer,
		.dataSize = len,
	};

	LOG_DBG("Page programming %d bytes to 0x%08x", len, offset);

	return flash_flexspi_transfer(data->controller, &transfer);
}

static int flash_flexspi_nor_wait_bus_busy(const struct device *dev)
{
	uint32_t status = 0;
	int ret;

	do {
		ret = flash_flexspi_nor_read_status(dev, &status);
		LOG_DBG("status: 0x%x", status);
		if (ret) {
			LOG_ERR("Could not read status");
			return ret;
		}
	} while (status & BIT(0));

	return 0;
}

static int flash_flexspi_nor_enable_octal_mode(const struct device *dev)
{
	struct flash_flexspi_nor_data *data = dev->data;
	uint32_t status = 0x02; //FLASH_ENABLE_OCTAL_CMD
	
	flash_flexspi_nor_write_enable(dev, false);
	flash_flexspi_nor_write_status(dev, &status);
	flash_flexspi_nor_wait_bus_busy(dev);
	flash_flexspi_reset(data->controller);

	return 0;
}

static int flash_flexspi_nor_read(const struct device *dev, off_t offset,
		void *buffer, size_t len)
{
	const struct flash_flexspi_nor_config *config = dev->config;
	struct flash_flexspi_nor_data *data = dev->data;

	flexspi_transfer_t transfer = {
		.deviceAddress = offset,
		.port = config->port,
		.cmdType = kFLEXSPI_Read,
		.SeqNumber = 1,
		.seqIndex = NOR_CMD_LUT_SEQ_IDX_READ,
		.data = (uint32_t *) buffer,
		.dataSize = len,
	};

	LOG_DBG("Reading %d bytes to 0x%08x", len, offset);

	return flash_flexspi_transfer(data->controller, &transfer);
}

static int flash_flexspi_nor_write(const struct device *dev, off_t offset,
		const void *buffer, size_t len)
{
	const struct flash_flexspi_nor_config *config = dev->config;
	struct flash_flexspi_nor_data *data = dev->data;
	size_t size = len;
	uint8_t *src = (uint8_t *) buffer;
	int i;

	uint8_t *dst = flash_flexspi_get_ahb_address(data->controller,
						     config->port,
						     offset);

	while (len) {
		i = MIN(SPI_NOR_PAGE_SIZE, len);
		flash_flexspi_nor_write_enable(dev, true);
		flash_flexspi_nor_page_program(dev, offset, src, i);
		flash_flexspi_nor_wait_bus_busy(dev);
		flash_flexspi_reset(data->controller);
		offset += i;
		len -= i;
	}

#ifdef CONFIG_HAS_MCUX_CACHE
	DCACHE_InvalidateByRange((uint32_t) dst, size);
#endif

	return 0;
}

static int flash_flexspi_nor_erase(const struct device *dev, off_t offset,
		size_t size)
{
	const struct flash_flexspi_nor_config *config = dev->config;
	struct flash_flexspi_nor_data *data = dev->data;
	int num_sectors = size / SPI_NOR_SECTOR_SIZE;
	int i;

	uint8_t *dst = flash_flexspi_get_ahb_address(data->controller,
						     config->port,
						     offset);

	if (offset % SPI_NOR_SECTOR_SIZE) {
		LOG_ERR("Invalid offset");
		return -EINVAL;
	}

	if (size % SPI_NOR_SECTOR_SIZE) {
		LOG_ERR("Invalid size");
		return -EINVAL;
	}

	if ((offset == 0) && (size == config->config.flashSize * KB(1))) {
		flash_flexspi_nor_write_enable(dev, true);
		flash_flexspi_nor_erase_chip(dev);
		flash_flexspi_nor_wait_bus_busy(dev);
		flash_flexspi_reset(data->controller);
	} else {
		for (i = 0; i < num_sectors; i++) {
			flash_flexspi_nor_write_enable(dev, true);
			flash_flexspi_nor_erase_sector(dev, offset);
			flash_flexspi_nor_wait_bus_busy(dev);
			flash_flexspi_reset(data->controller);
			offset += SPI_NOR_SECTOR_SIZE;
		}
	}

#ifdef CONFIG_HAS_MCUX_CACHE
	DCACHE_InvalidateByRange((uint32_t) dst, size);
#endif

	return 0;
}

static int flash_flexspi_nor_write_protection(const struct device *dev,
		bool enable)
{
	return 0;
}

static const struct flash_parameters *flash_flexspi_nor_get_parameters(
		const struct device *dev)
{
	const struct flash_flexspi_nor_config *config = dev->config;

	return &config->flash_parameters;
}

#if defined(CONFIG_FLASH_PAGE_LAYOUT)
static void flash_flexspi_nor_pages_layout(const struct device *dev,
		const struct flash_pages_layout **layout, size_t *layout_size)
{
	const struct flash_flexspi_nor_config *config = dev->config;

	*layout = &config->layout;
	*layout_size = 1;
}
#endif /* CONFIG_FLASH_PAGE_LAYOUT */

static int flash_flexspi_nor_init(const struct device *dev)
{
	uint32_t customLUT[CUSTOM_LUT_LENGTH] = {

	    [4 * NOR_CMD_LUT_SEQ_IDX_READ + 0] =
		FLEXSPI_LUT_SEQ(kFLEXSPI_Command_SDR, kFLEXSPI_8PAD, 0xEC, kFLEXSPI_Command_SDR, kFLEXSPI_8PAD, 0x13),
	    [4 * NOR_CMD_LUT_SEQ_IDX_READ + 1] = FLEXSPI_LUT_SEQ(
		kFLEXSPI_Command_RADDR_SDR, kFLEXSPI_8PAD, 0x20, kFLEXSPI_Command_DUMMY_SDR, kFLEXSPI_8PAD, 0x14),
	    [4 * NOR_CMD_LUT_SEQ_IDX_READ + 2] =
		FLEXSPI_LUT_SEQ(kFLEXSPI_Command_READ_SDR, kFLEXSPI_8PAD, 0x04, kFLEXSPI_Command_STOP, kFLEXSPI_1PAD, 0x0),

	    [4 * NOR_CMD_LUT_SEQ_IDX_READSTATUS] =
		FLEXSPI_LUT_SEQ(kFLEXSPI_Command_SDR, kFLEXSPI_1PAD, 0x05, kFLEXSPI_Command_READ_SDR, kFLEXSPI_1PAD, 0x04),

	    [4 * NOR_CMD_LUT_SEQ_IDX_WRITEENABLE] =
		FLEXSPI_LUT_SEQ(kFLEXSPI_Command_SDR, kFLEXSPI_1PAD, 0x06, kFLEXSPI_Command_STOP, kFLEXSPI_1PAD, 0),

	    [4 * NOR_CMD_LUT_SEQ_IDX_READID_OPI] =
		FLEXSPI_LUT_SEQ(kFLEXSPI_Command_SDR, kFLEXSPI_8PAD, 0x9F, kFLEXSPI_Command_SDR, kFLEXSPI_8PAD, 0x60),
	    [4 * NOR_CMD_LUT_SEQ_IDX_READID_OPI + 1] = FLEXSPI_LUT_SEQ(
		kFLEXSPI_Command_RADDR_SDR, kFLEXSPI_8PAD, 0x20, kFLEXSPI_Command_DUMMY_SDR, kFLEXSPI_8PAD, 0x16),
	    [4 * NOR_CMD_LUT_SEQ_IDX_READID_OPI + 2] =
		FLEXSPI_LUT_SEQ(kFLEXSPI_Command_READ_SDR, kFLEXSPI_8PAD, 0x04, kFLEXSPI_Command_STOP, kFLEXSPI_1PAD, 0x0),

	    [4 * NOR_CMD_LUT_SEQ_IDX_WRITEENABLE_OPI] =
		FLEXSPI_LUT_SEQ(kFLEXSPI_Command_SDR, kFLEXSPI_8PAD, 0x06, kFLEXSPI_Command_SDR, kFLEXSPI_8PAD, 0xF9),

	    [4 * NOR_CMD_LUT_SEQ_IDX_ERASESECTOR] =
		FLEXSPI_LUT_SEQ(kFLEXSPI_Command_SDR, kFLEXSPI_8PAD, 0x21, kFLEXSPI_Command_SDR, kFLEXSPI_8PAD, 0xDE),
	    [4 * NOR_CMD_LUT_SEQ_IDX_ERASESECTOR + 1] =
		FLEXSPI_LUT_SEQ(kFLEXSPI_Command_RADDR_SDR, kFLEXSPI_8PAD, 0x20, kFLEXSPI_Command_STOP, kFLEXSPI_8PAD, 0),

	    [4 * NOR_CMD_LUT_SEQ_IDX_CHIPERASE] =
		FLEXSPI_LUT_SEQ(kFLEXSPI_Command_SDR, kFLEXSPI_8PAD, 0x60, kFLEXSPI_Command_SDR, kFLEXSPI_8PAD, 0x9F),

	    [4 * NOR_CMD_LUT_SEQ_IDX_PAGEPROGRAM] =
		FLEXSPI_LUT_SEQ(kFLEXSPI_Command_SDR, kFLEXSPI_8PAD, 0x12, kFLEXSPI_Command_SDR, kFLEXSPI_8PAD, 0xED),
	    [4 * NOR_CMD_LUT_SEQ_IDX_PAGEPROGRAM + 1] = FLEXSPI_LUT_SEQ(
		kFLEXSPI_Command_RADDR_SDR, kFLEXSPI_8PAD, 0x20, kFLEXSPI_Command_WRITE_SDR, kFLEXSPI_8PAD, 0x04),
/*          
            // SDK enter OPI sequence
	    [4 * NOR_CMD_LUT_SEQ_IDX_ENTEROPI] =
		FLEXSPI_LUT_SEQ(kFLEXSPI_Command_SDR, kFLEXSPI_1PAD, 0x72, kFLEXSPI_Command_RADDR_SDR, kFLEXSPI_1PAD, 0x20),
	    [4 * NOR_CMD_LUT_SEQ_IDX_ENTEROPI + 1] =
		FLEXSPI_LUT_SEQ(kFLEXSPI_Command_WRITE_SDR, kFLEXSPI_1PAD, 0x04, kFLEXSPI_Command_STOP, kFLEXSPI_1PAD, 0),
*/
	    // boot ROM: "Enable OPI SDR mode" sequence
	    [4 * NOR_CMD_LUT_SEQ_IDX_ENTEROPI] =
		FLEXSPI_LUT_SEQ(kFLEXSPI_Command_SDR, kFLEXSPI_1PAD, 0x72, kFLEXSPI_Command_SDR, kFLEXSPI_1PAD, 0x0),
	    [4 * NOR_CMD_LUT_SEQ_IDX_ENTEROPI + 1] =
		FLEXSPI_LUT_SEQ(kFLEXSPI_Command_SDR, kFLEXSPI_1PAD, 0x0, kFLEXSPI_Command_SDR, kFLEXSPI_1PAD, 0x03),
	    [4 * NOR_CMD_LUT_SEQ_IDX_ENTEROPI + 2] =
		FLEXSPI_LUT_SEQ(kFLEXSPI_Command_SDR, kFLEXSPI_1PAD, 0x00, kFLEXSPI_Command_WRITE_SDR, kFLEXSPI_1PAD, 0x01),
		
	    [4 * NOR_CMD_LUT_SEQ_IDX_WRITE] =
		FLEXSPI_LUT_SEQ(kFLEXSPI_Command_STOP, kFLEXSPI_1PAD, 0x0, kFLEXSPI_Command_STOP, kFLEXSPI_1PAD, 0x0),

	    [4 * NOR_CMD_LUT_SEQ_IDX_READSTATUS_OPI] =
		FLEXSPI_LUT_SEQ(kFLEXSPI_Command_SDR, kFLEXSPI_8PAD, 0x05, kFLEXSPI_Command_SDR, kFLEXSPI_8PAD, 0xFA),
	    [4 * NOR_CMD_LUT_SEQ_IDX_READSTATUS_OPI + 1] = FLEXSPI_LUT_SEQ(
		kFLEXSPI_Command_RADDR_SDR, kFLEXSPI_8PAD, 0x20, kFLEXSPI_Command_DUMMY_SDR, kFLEXSPI_8PAD, 0x14),
	    [4 * NOR_CMD_LUT_SEQ_IDX_READSTATUS_OPI + 2] =
		FLEXSPI_LUT_SEQ(kFLEXSPI_Command_READ_SDR, kFLEXSPI_8PAD, 0x04, kFLEXSPI_Command_STOP, kFLEXSPI_1PAD, 0x0),
	};

	const struct flash_flexspi_nor_config *config = dev->config;
	struct flash_flexspi_nor_data *data = dev->data;
	uint8_t vendor_id;
	//uint32_t localLUT[CUSTOM_LUT_LENGTH];
	
	//memcpy(localLUT, customLUT, sizeof(customLUT));
	
	data->controller = device_get_binding(config->controller_label);
	if (data->controller == NULL) {
		LOG_ERR("Could not find controller");
		return -EINVAL;
	}


	if (flash_flexspi_set_flash_config(data->controller, &config->config,
					   config->port)) {
		LOG_ERR("Could not set flash configuration");
		return -EINVAL;
	}
	
	if (flash_flexspi_update_lut(data->controller, 0,
				     (const uint32_t *) customLUT,
				     CUSTOM_LUT_LENGTH)) {
		LOG_ERR("Could not update lut");
		return -EINVAL;
	}

	flash_flexspi_reset(data->controller);

	if (flash_flexspi_nor_enable_octal_mode(dev)) {
		LOG_ERR("Could not enable octal mode");
		return -EIO;
	}
	
	if (flash_flexspi_nor_get_vendor_id(dev, &vendor_id)) {
		LOG_ERR("Could not read vendor id");
		return -EIO;
	}
	LOG_DBG("Vendor id: 0x%0x", vendor_id);
	
	return 0;
}

static const struct flash_driver_api flash_flexspi_nor_api = {
	.write_protection = flash_flexspi_nor_write_protection,
	.erase = flash_flexspi_nor_erase,
	.write = flash_flexspi_nor_write,
	.read = flash_flexspi_nor_read,
	.get_parameters = flash_flexspi_nor_get_parameters,
#if defined(CONFIG_FLASH_PAGE_LAYOUT)
	.page_layout = flash_flexspi_nor_pages_layout,
#endif
};

#define CONCAT3(x, y, z) x ## y ## z

#define CS_INTERVAL_UNIT(unit)						\
	CONCAT3(kFLEXSPI_CsIntervalUnit, unit, SckCycle)

#define AHB_WRITE_WAIT_UNIT(unit)					\
	CONCAT3(kFLEXSPI_AhbWriteWaitUnit, unit, AhbCycle)

#define FLASH_FLEXSPI_DEVICE_CONFIG(n)					\
	{								\
		.flexspiRootClk = MHZ(99),				\
		.flashSize = DT_INST_PROP(n, size) / 8 / KB(1),		\
		.CSIntervalUnit =0,					\
		.CSInterval = DT_INST_PROP(n, cs_interval),		\
		.CSHoldTime = DT_INST_PROP(n, cs_hold_time),		\
		.CSSetupTime = DT_INST_PROP(n, cs_setup_time),		\
		.dataValidTime = DT_INST_PROP(n, data_valid_time),	\
		.columnspace = 0,					\
		.enableWordAddress = 0,					\
		.AWRSeqIndex = NOR_CMD_LUT_SEQ_IDX_WRITE,		\
		.AWRSeqNumber = 1,					\
		.ARDSeqIndex = NOR_CMD_LUT_SEQ_IDX_READ,		\
		.ARDSeqNumber = 1,					\
		.AHBWriteWaitUnit = 0,					\
		.AHBWriteWaitInterval =					\
			DT_INST_PROP(n, ahb_write_wait_interval),	\
	}								\

#define FLASH_FLEXSPI_NOR(n)						\
	static const struct flash_flexspi_nor_config			\
		flash_flexspi_nor_config_##n = {			\
		.controller_label = DT_INST_BUS_LABEL(n),		\
		.port = DT_INST_REG_ADDR(n),				\
		.config = FLASH_FLEXSPI_DEVICE_CONFIG(n),		\
		.layout = {						\
			.pages_count = DT_INST_PROP(n, size) / 8	\
				/ SPI_NOR_SECTOR_SIZE,			\
			.pages_size = SPI_NOR_SECTOR_SIZE,		\
		},							\
		.flash_parameters = {					\
			.write_block_size = NOR_WRITE_SIZE,		\
			.erase_value = NOR_ERASE_VALUE,			\
		},							\
	};								\
									\
	static struct flash_flexspi_nor_data				\
		flash_flexspi_nor_data_##n;				\
									\
	DEVICE_DT_INST_DEFINE(n,					\
			      flash_flexspi_nor_init,			\
			      device_pm_control_nop,			\
			      &flash_flexspi_nor_data_##n,		\
			      &flash_flexspi_nor_config_##n,		\
			      POST_KERNEL,				\
			      CONFIG_KERNEL_INIT_PRIORITY_DEVICE,	\
			      &flash_flexspi_nor_api);

DT_INST_FOREACH_STATUS_OKAY(FLASH_FLEXSPI_NOR)
