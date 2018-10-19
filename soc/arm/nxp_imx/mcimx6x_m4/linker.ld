/*
 * Copyright (c) 2014 Wind River Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <autoconf.h>

/* Specify the shared memory area */
MEMORY
{
  heap_mem_pool          (RW)  : ORIGIN = 0x84400000, LENGTH = 0x400000
}

SECTIONS
{
  /* NOINIT section for heap_mem_pool */
  .noinit_heap_mem_pool (NOLOAD) : ALIGN(4)
  {
     *(.noinit.$heap_mem_pool*)
     . = ALIGN(4) ;
  } > heap_mem_pool
}

#include <arch/arm/cortex_m/scripts/linker.ld>
