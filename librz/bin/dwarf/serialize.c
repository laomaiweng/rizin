// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin_dwarf.h>
#include "dwarf_private.h"

static bool save_section(const char *name, RzBuffer *buffer, Sdb *sdb) {
	if (!buffer) {
		return false;
	}
	ut8 *bin = NULL;
	char *bin64 = NULL;
	ut64 sz = rz_buf_size(buffer);
	bin = RZ_NEWS(ut8, sz);
	rz_buf_seek(buffer, 0, RZ_BUF_SET);
	if (rz_buf_read(buffer, bin, sz) != sz) {
		goto err;
	}
	bin64 = rz_base64_encode_dyn(bin, sz);
	if (!bin64) {
		goto err;
	}
	sdb_set_owned(sdb, name, bin64, 0);
	free(bin);
	return true;
err:
	free(bin);
	return false;
}

#define TRY_SAVE_SECTION(name, X) \
	if (X) { \
		save_section(name, X->buffer, sdb); \
	}

RZ_API bool rz_bin_dwarf_serialize_sdb(const RzBinDWARF *dw, Sdb *sdb) {
	rz_return_val_if_fail(dw, false);
	TRY_SAVE_SECTION(".debug_aranges", dw->aranges);
	TRY_SAVE_SECTION(".debug_abbrevs", dw->abbrev);
	TRY_SAVE_SECTION(".debug_info", dw->info);
	TRY_SAVE_SECTION(".debug_str", dw->str);
	TRY_SAVE_SECTION(".debug_addr", dw->addr);
	TRY_SAVE_SECTION(".debug_line", dw->line);
	if (dw->loc) {
		save_section(".debug_loc", dw->loc->debug_loc, sdb);
		save_section(".debug_loclists", dw->loc->debug_loclists, sdb);
	}
	if (dw->rng) {
		save_section(".debug_ranges", dw->rng->debug_ranges, sdb);
		save_section(".debug_rnglists", dw->rng->debug_rnglists, sdb);
	}
	return true;
}