MEMORY {
  /* PP2/W has 16MB of external flash and 8M of PSRAM */
  FLASH : ORIGIN =       0x10000000, LENGTH = 16M
  PSRAM : ORIGIN = 0x10000000 + 16M, LENGTH = 8M

  /* RAM banks 0 through 7 are striped, use uniformly */
  RAM   : ORIGIN =       0x20000000, LENGTH = 512K

  /* RAM banks 8 and 9 are directly mapped */
  SRAM4 : ORIGIN =       0x20080000, LENGTH = 4K
  SRAM5 : ORIGIN =       0x20081000, LENGTH = 4K
}

SECTIONS {
  /*
   * Boot ROM info, goes after .vector_table
   * to be in the first 4K of flash so the
   * Boot ROM can find it
   */
  .start_block : ALIGN(4) {
    __start_block_addr = .;
    KEEP(*(.start_block));
    KEEP(*(.boot_info));
  } > FLASH
} INSERT AFTER .vector_table;

/* Move .text to after the boot info */
_stext = ADDR(.start_block) + SIZEOF(.start_block);

SECTIONS {
  /* Picotool Binary Info entries */
  .bi_entries : ALIGN(4) {
    __bi_entries_start = .;
    KEEP(*(.bi_entries));
    /* Keep this block a round size */
    . = ALIGN(4);
    __bi_entries_end = .;
  } > FLASH
} INSERT AFTER .text;

SECTIONS {
  /*
   * Boot ROM extra info, goes after everything else
   * so it can contain a signature.
   */
  .end_block : ALIGN(4) {
    __end_block_addr = .;
    KEEP(*(.end_block));
  } > FLASH
} INSERT AFTER .uninit;

PROVIDE(start_to_end = __end_block_addr - __start_block_addr);
PROVIDE(end_to_start = __start_block_addr - __end_block_addr);
