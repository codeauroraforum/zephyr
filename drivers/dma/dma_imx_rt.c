/*
 * Copyright (c) 2020 NXP Semiconductor INC.
 * All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @brief Common part of DMA drivers for imx rt series.
 */

#include <errno.h>
#include <soc.h>
#include <init.h>
#include <kernel.h>
#include <drivers/dma.h>
#include <drivers/clock_control.h>

#include "dma_imx_rt.h"

#include <logging/log.h>
LOG_MODULE_REGISTER(dma_imx_rt, CONFIG_DMA_LOG_LEVEL);

struct dma_imx_rt_config {
	DMA_Type *base;
	DMAMUX_Type *dmamux_base;
	void (*irq_config_func)(struct device *dev);
};

static __aligned(32) edma_tcd_t
	tcdpool[DT_INST_0_NXP_IMX_EDMA_DMA_CHANNELS][CONFIG_DMA_TCD_QUEUE_SIZE];

struct call_back {
	edma_transfer_config_t transferConfig;
	edma_handle_t edma_handle;
	void *callback_arg;
	void (*dma_callback)(void *callback_arg, u32_t channel, int error_code);
	enum dma_channel_direction dir;
	bool busy;
};

struct dma_imx_rt_data {
	struct call_back data_cb[DT_INST_0_NXP_IMX_EDMA_DMA_CHANNELS];
};

#define DEV_CFG(dev)                                                           \
	((const struct dma_imx_rt_config *const)dev->config->config_info)
#define DEV_DATA(dev) ((struct dma_imx_rt_data *)dev->driver_data)
#define DEV_BASE(dev) ((DMA_Type *)DEV_CFG(dev)->base)

#define DEV_DMAMUX_BASE(dev) ((DMAMUX_Type *)DEV_CFG(dev)->dmamux_base)

#define DEV_CHANNEL_DATA(dev, ch)                                              \
	((struct call_back *)(&(DEV_DATA(dev)->data_cb[ch])))

#define DEV_EDMA_HANDLE(dev, ch)                                               \
	((edma_handle_t *)(&(DEV_CHANNEL_DATA(dev, ch)->edma_handle)))

static void _edma_callback(edma_handle_t *handle, void *param,
			   bool transferDone, uint32_t tcds)
{
	int ret = 1;
	struct call_back *data = (struct call_back *)param;
	u32_t channel = handle->channel;
	if (transferDone) {
		data->busy = false;
		ret = 0;
	}
	LOG_DBG("transfer %d", tcds);
	data->dma_callback(data->callback_arg, channel, ret);
}

static void _channel_irq(edma_handle_t *handle)
{
	bool transfer_done;

	/* Clear EDMA interrupt flag */
	handle->base->CINT = handle->channel;
	/* Check if transfer is already finished. */
	transfer_done = ((handle->base->TCD[handle->channel].CSR &
			  DMA_CSR_DONE_MASK) != 0U);

	if (handle->tcdPool == NULL) {
		(handle->callback)(handle, handle->userData, transfer_done, 0);
	} else /* Use the TCD queue. Please refer to the API descriptions in the eDMA header file for detailed information. */
	{
		uint32_t sga = handle->base->TCD[handle->channel].DLAST_SGA;
		uint32_t sga_index;
		int32_t tcds_done;
		uint8_t new_header;

		/* Get the offset of the next transfer TCD blocks to be loaded into the eDMA engine. */
		sga -= (uint32_t)handle->tcdPool;
		/* Get the index of the next transfer TCD blocks to be loaded into the eDMA engine. */
		sga_index = sga / sizeof(edma_tcd_t);
		/* Adjust header positions. */
		if (transfer_done) {
			/* New header shall point to the next TCD to be loaded (current one is already finished) */
			new_header = (uint8_t)sga_index;
		} else {
			/* New header shall point to this descriptor currently loaded (not finished yet) */
			new_header = sga_index != 0U ?
					     (uint8_t)sga_index - 1U :
					     (uint8_t)handle->tcdSize - 1U;
		}
		/* Calculate the number of finished TCDs */
		if (new_header == (uint8_t)handle->header) {
			int8_t tmpTcdUsed = handle->tcdUsed;
			int8_t tmpTcdSize = handle->tcdSize;

			if (tmpTcdUsed == tmpTcdSize) {
				tcds_done = handle->tcdUsed;
			} else {
				/* No TCD in the memory are going to be loaded or internal error occurs. */
				tcds_done = 0;
			}
		} else {
			tcds_done =
				(uint32_t)new_header - (uint32_t)handle->header;
			if (tcds_done < 0) {
				tcds_done += handle->tcdSize;
			}
		}
		/* Advance header which points to the TCD to be loaded into the eDMA engine from memory. */
		handle->header = (int8_t)new_header;
		/* Release TCD blocks. tcdUsed is the TCD number which can be used/loaded in the memory pool. */
		handle->tcdUsed -= (int8_t)tcds_done;
		/* Invoke callback function. */
		if (NULL != handle->callback) {
			(handle->callback)(handle, handle->userData,
					   transfer_done, tcds_done);
		}

		/* clear the DONE bit here is meaningful for below cases:
         *1.A new TCD has been loaded to EDMA already:
         * need to clear the DONE bit in the IRQ handler to avoid TCD in EDMA been overwritten
         * if peripheral request isn't coming before next transfer request.
         *2.A new TCD has not been loaded to EDMA:
         * for the case that transfer request occur in the privious edma callback, this is a case that doesn't
         * need scatter gather, so keep DONE bit during the next transfer request will re-install the TCD.
         */
		if (transfer_done) {
			handle->base->CDNE = handle->channel;
		}
	}
}

static void dma_imx_rt_irq_handler(void *arg)
{
	struct device *dev = (struct device *)arg;
	int i = 0;
	LOG_DBG("IRQ CALLED");
	for (i = 0; i < DT_INST_0_NXP_IMX_EDMA_DMA_CHANNELS; i++) {
		if (DEV_CHANNEL_DATA(dev, i)->busy) {
			u32_t flag =
				EDMA_GetChannelStatusFlags(DEV_BASE(dev), i);
			if ((flag & (uint32_t)kEDMA_InterruptFlag) != 0U) {
				LOG_DBG("IRQ OCCURRED");
				_channel_irq(DEV_EDMA_HANDLE(dev, i));
				LOG_DBG("IRQ DONE");
#if defined __CORTEX_M && (__CORTEX_M == 4U)
				__DSB();
#endif
			} else {
				LOG_DBG("flag is 0x%x", flag);
				LOG_DBG("DMA ES 0x%x", DEV_BASE(dev)->ES);
				LOG_DBG("channel id %d", i);
				EDMA_ClearChannelStatusFlags(
					DEV_BASE(dev), i,
					kEDMA_ErrorFlag | kEDMA_DoneFlag);
				EDMA_AbortTransfer(DEV_EDMA_HANDLE(dev, i));
			}
		}
	}
}

static void dma_imx_rt_error_irq_handler(void *arg)
{
	int i = 0;
	u32_t flag = 0;
	struct device *dev = (struct device *)arg;
	for (i = 0; i < DT_INST_0_NXP_IMX_EDMA_DMA_CHANNELS; i++) {
		if (DEV_CHANNEL_DATA(dev, i)->busy) {
			flag = EDMA_GetChannelStatusFlags(DEV_BASE(dev), i);
			LOG_INF("channel %d error status is 0x%x", i, flag);
			EDMA_ClearChannelStatusFlags(DEV_BASE(dev), i,
						     0xFFFFFFFF);
			EDMA_AbortTransfer(DEV_EDMA_HANDLE(dev, i));
			DEV_CHANNEL_DATA(dev, i)->busy = false;
		}
	}

#if defined __CORTEX_M && (__CORTEX_M == 4U)
	__DSB();
#endif

	return;
}

static void dam_imx_rt_set_channel_priority(struct device *dev, u32_t channel,
					   struct dma_config *config)
{
	edma_channel_Preemption_config_t channel_priority;

	channel_priority.enableChannelPreemption = true;
	channel_priority.enablePreemptAbility = true;
	channel_priority.channelPriority = config->channel_priority;
	/*FIX ME channel need disabled first*/
	EDMA_SetChannelPreemptionConfig(DEV_BASE(dev), channel,
					&channel_priority);
}

/* Configure a channel */
static int dma_imx_rt_configure(struct device *dev, u32_t channel,
				struct dma_config *config)
{
	edma_handle_t *p_handle = DEV_EDMA_HANDLE(dev, channel);
	struct call_back *data = DEV_CHANNEL_DATA(dev, channel);
	struct dma_block_config *block_config = config->head_block;
	u32_t slot = config->dma_slot;
	edma_transfer_type_t transfer_type;
	int key;

	if (NULL == dev || NULL == config) {
		return -EINVAL;
	}

	if (slot > DT_INST_0_NXP_IMX_EDMA_DMA_REQUESTS) {
		LOG_ERR("source number is outof scope %d", slot);
		return -ENOTSUP;
	}

	if (channel > DT_INST_0_NXP_IMX_EDMA_DMA_CHANNELS) {
		LOG_ERR("out of DMA channel %d", channel);
		return -EINVAL;
	}

	data->dir = config->channel_direction;
	switch (config->channel_direction) {
	case MEMORY_TO_MEMORY:
		transfer_type = kEDMA_MemoryToMemory;
		break;
	case MEMORY_TO_PERIPHERAL:
		transfer_type = kEDMA_MemoryToPeripheral;
		break;
	case PERIPHERAL_TO_MEMORY:
		transfer_type = kEDMA_PeripheralToMemory;
		break;
	case PERIPHERAL_TO_PERIPHERAL:
		transfer_type = kEDMA_PeripheralToPeripheral;
		break;
	default:
		LOG_ERR("not support transfer direction");
		return -EINVAL;
	}

	/* Lock and page in the channel configuration */
	key = irq_lock();

#if DT_INST_0_NXP_IMX_EDMA_NXP_A_ON
	if (config->source_handshake || config->dest_handshake ||
	    transfer_type == kEDMA_MemoryToMemory) {
		/*software trigger make the channel always on*/
		LOG_DBG("ALWAYS ON");
		DMAMUX_EnableAlwaysOn(DEV_DMAMUX_BASE(dev), channel, true);
	} else {
		DMAMUX_SetSource(DEV_DMAMUX_BASE(dev), channel, slot);
	}
#else
	DMAMUX_SetSource(DEV_DMAMUX_BASE(dev), channel, slot);
#endif

	/* 
	dam_imx_rt_set_channel_priority(dev, channel, config);
	*/
	DMAMUX_EnableChannel(DEV_DMAMUX_BASE(dev), channel);

	if (data->busy) {
		EDMA_AbortTransfer(p_handle);
	}
	EDMA_ResetChannel(DEV_BASE(dev), channel);
	EDMA_CreateHandle(p_handle, DEV_BASE(dev), channel);
	EDMA_SetCallback(p_handle, _edma_callback, (void *)data);

	LOG_DBG("channel is %d", p_handle->channel);

	if (config->source_data_size != 4U && config->source_data_size != 2U &&
	    config->source_data_size != 1U && config->source_data_size != 8U &&
	    config->source_data_size != 16U &&
	    config->source_data_size != 32U) {
		LOG_ERR("Source unit size error, %d", config->source_data_size);
		return -EINVAL;
	}

	if (config->dest_data_size != 4U && config->dest_data_size != 2U &&
	    config->dest_data_size != 1U && config->dest_data_size != 8U &&
	    config->dest_data_size != 16U && config->dest_data_size != 32U) {
		LOG_ERR("Dest unit size error, %d", config->dest_data_size);
		return -EINVAL;
	}

	EDMA_EnableChannelInterrupts(DEV_BASE(dev), channel,
				     kEDMA_ErrorInterruptEnable);

	if (config->source_chaining_en && config->dest_chaining_en) {
		/*chaining mode only support major link*/
		LOG_DBG("link major channel %d", config->linked_channel);
		EDMA_SetChannelLink(DEV_BASE(dev), channel, kEDMA_MajorLink,
				    config->linked_channel);
	}

	if (block_config->source_gather_en || block_config->dest_scatter_en) {
		if (config->block_count > CONFIG_DMA_TCD_QUEUE_SIZE) {
			LOG_ERR("please config DMA_TCD_QUEUE_SIZE as %d",
				config->block_count);
			return -EINVAL;
		}
		EDMA_InstallTCDMemory(p_handle, tcdpool[channel],
				      CONFIG_DMA_TCD_QUEUE_SIZE);
		while (NULL != block_config) {
			EDMA_PrepareTransfer(
				&(data->transferConfig),
				(void *)block_config->source_address,
				config->source_data_size,
				(void *)block_config->dest_address,
				config->dest_data_size,
				config->source_burst_length,
				block_config->block_size, transfer_type);
			EDMA_SubmitTransfer(p_handle, &(data->transferConfig));
			block_config = block_config->next_block;
		}
	} else {
		/*fix me block_count shall be 1 
         *and only 1 block_config is used
		 */
		status_t ret;
		EDMA_PrepareTransfer(&(data->transferConfig),
				     (void *)block_config->source_address,
				     config->source_data_size,
				     (void *)block_config->dest_address,
				     config->dest_data_size,
				     config->source_burst_length,
				     block_config->block_size, transfer_type);

		ret = EDMA_SubmitTransfer(p_handle, &(data->transferConfig));
		edma_tcd_t *tcdRegs =
			(edma_tcd_t *)(uint32_t)&p_handle->base->TCD[channel];
		if (ret != kStatus_Success) {
			LOG_ERR("submit error 0x%x", ret);
		}
		LOG_DBG("data csr is 0x%x", tcdRegs->CSR);
	}

	data->busy = false;
	if (config->dma_callback) {
		LOG_DBG("INSTALL call back on channel %d", channel);
		data->callback_arg = config->callback_arg;
		data->dma_callback = config->dma_callback;
	}

	irq_unlock(key);

	return 0;
}

static int dma_imx_rt_start(struct device *dev, u32_t channel)
{
	struct call_back *data = DEV_CHANNEL_DATA(dev, channel);
	LOG_DBG("START TRANSFER");
	LOG_DBG("DMAMUX CHCFG 0x%x", DEV_DMAMUX_BASE(dev)->CHCFG[channel]);
	LOG_DBG("DMA CR 0x%x", DEV_BASE(dev)->CR);
	data->busy = true;
	EDMA_StartTransfer(DEV_EDMA_HANDLE(dev, channel));
	return 0;
}

static int dma_imx_rt_stop(struct device *dev, u32_t channel)
{
	struct dma_imx_rt_data *data = DEV_DATA(dev);
	if (!data->data_cb[channel].busy) {
		return 0;
	}
	EDMA_AbortTransfer(DEV_EDMA_HANDLE(dev, channel));
	EDMA_ClearChannelStatusFlags(DEV_BASE(dev), channel,
				     kEDMA_DoneFlag | kEDMA_ErrorFlag |
					     kEDMA_InterruptFlag);
	EDMA_ResetChannel(DEV_BASE(dev), channel);
	data->data_cb[channel].busy = false;
	return 0;
}

static int dma_imx_rt_reload(struct device *dev, u32_t channel, u32_t src,
			     u32_t dst, size_t size)
{
	struct call_back *data = DEV_CHANNEL_DATA(dev, channel);
	if (data->busy) {
		EDMA_AbortTransfer(DEV_EDMA_HANDLE(dev, channel));
	}
	return 0;
}

static int dma_imx_rt_get_status(struct device *dev, u32_t channel,
				 struct dma_status *status)
{
	edma_tcd_t *tcdRegs;
	if (DEV_CHANNEL_DATA(dev, channel)->busy) {
		status->busy = true;
		status->pending_length =
			EDMA_GetRemainingMajorLoopCount(DEV_BASE(dev), channel);
	} else {
		status->busy = false;
		status->pending_length = 0;
	}
	status->dir = DEV_CHANNEL_DATA(dev, channel)->dir;
	LOG_DBG("DMAMUX CHCFG 0x%x", DEV_DMAMUX_BASE(dev)->CHCFG[channel]);
	LOG_DBG("DMA CR 0x%x", DEV_BASE(dev)->CR);
	LOG_DBG("DMA INT 0x%x", DEV_BASE(dev)->INT);
	LOG_DBG("DMA ERQ 0x%x", DEV_BASE(dev)->ERQ);
	LOG_DBG("DMA ES 0x%x", DEV_BASE(dev)->ES);
	LOG_DBG("DMA ERR 0x%x", DEV_BASE(dev)->ERR);
	LOG_DBG("DMA HRS 0x%x", DEV_BASE(dev)->HRS);
	tcdRegs = (edma_tcd_t *)((uint32_t)&DEV_BASE(dev)->TCD[channel]);
	LOG_DBG("data csr is 0x%x", tcdRegs->CSR);
	return 0;
}

static const struct dma_driver_api dma_imx_rt_api = {
	.reload = dma_imx_rt_reload,
	.config = dma_imx_rt_configure,
	.start = dma_imx_rt_start,
	.stop = dma_imx_rt_stop,
	.get_status = dma_imx_rt_get_status,
};

static int dma_imx_rt_init(struct device *dev)
{
	edma_config_t userConfig = { 0 };
	LOG_DBG("INIT NXP DMA");
	DMAMUX_Init(DEV_DMAMUX_BASE(dev));
	EDMA_GetDefaultConfig(&userConfig);
	EDMA_Init(DEV_BASE(dev), &userConfig);
	DEV_CFG(dev)->irq_config_func(dev);
	memset(DEV_DATA(dev), 0, sizeof(struct dma_imx_rt_data));
	memset(tcdpool, 0, sizeof(tcdpool));
	return 0;
}

static void dma_imx_config_func_0(struct device *dev);

static const struct dma_imx_rt_config dma_config_0 = {
	.base = (DMA_Type *)DT_INST_0_NXP_IMX_EDMA_BASE_ADDRESS_0,
	.dmamux_base = (DMAMUX_Type *)DT_INST_0_NXP_IMX_EDMA_BASE_ADDRESS_1,
	.irq_config_func = dma_imx_config_func_0,
};

struct dma_imx_rt_data dma_data;
/*
 * define the dma
 */
DEVICE_AND_API_INIT(dma_imx_rt_0, CONFIG_DMA_0_NAME, &dma_imx_rt_init,
		    &dma_data, &dma_config_0, POST_KERNEL,
		    CONFIG_KERNEL_INIT_PRIORITY_DEVICE, &dma_imx_rt_api);

#define IRQ_INIT(dma, chan)                                                    \
	do {                                                                   \
		IRQ_CONNECT(                                                   \
			DT_INST_##dma##_NXP_IMX_EDMA_IRQ_##chan,               \
			DT_INST_##dma##_NXP_IMX_EDMA_IRQ_##chan##_PRIORITY,    \
			dma_imx_rt_irq_handler, DEVICE_GET(dma_imx_rt_0), 0);  \
		irq_enable(DT_INST_##dma##_NXP_IMX_EDMA_IRQ_##chan);           \
	} while (0)

#define ERROR_IRQ_INIT(dma, chan)                                              \
	do {                                                                   \
		IRQ_CONNECT(                                                   \
			DT_INST_##dma##_NXP_IMX_EDMA_IRQ_##chan,               \
			DT_INST_##dma##_NXP_IMX_EDMA_IRQ_##chan##_PRIORITY,    \
			dma_imx_rt_error_irq_handler,                          \
			DEVICE_GET(dma_imx_rt_0), 0);                          \
		irq_enable(DT_INST_##dma##_NXP_IMX_EDMA_IRQ_##chan);           \
	} while (0)

void dma_imx_config_func_0(struct device *dev)
{
	ARG_UNUSED(dev);

/*install the dma error handle*/
#if 1
	IRQ_INIT(0, 0);
	IRQ_INIT(0, 1);
	IRQ_INIT(0, 2);
	IRQ_INIT(0, 3);
	IRQ_INIT(0, 4);
	IRQ_INIT(0, 5);
	IRQ_INIT(0, 6);
	IRQ_INIT(0, 7);
	IRQ_INIT(0, 8);
	IRQ_INIT(0, 9);
	IRQ_INIT(0, 10);
	IRQ_INIT(0, 11);
	IRQ_INIT(0, 12);
	IRQ_INIT(0, 13);
	IRQ_INIT(0, 14);
	IRQ_INIT(0, 15);
	ERROR_IRQ_INIT(0, 16);
#endif
	LOG_DBG("install irq done");
	return;
}
