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

static RzBuffer *load_section(const char *name, Sdb *sdb) {
	ut8 *bin = NULL;
	const char *bin64 = sdb_const_get(sdb, name, 0);
	if (!bin64) {
		return NULL;
	}
	bin = rz_base64_decode_dyn(bin64, -1);
	if (!bin) {
		return NULL;
	}
	return rz_buf_new_with_pointers(bin, strlen((char *)bin), true);
}

#define TRY_SAVE_SECTION(name, X) \
	if (X) { \
		save_section(name, X->buffer, sdb); \
	}

RZ_API bool rz_bin_dwarf_serialize_sdb(const RzBinDWARF *dw, Sdb *sdb) {
	rz_return_val_if_fail(dw, false);
	sdb_bool_set(sdb, "big_endian", dw->encoding.big_endian, 0);
	sdb_bool_set(sdb, "is_64bit", dw->encoding.is_64bit, 0);
	sdb_num_set(sdb, "address_size", dw->encoding.address_size, 0);
	sdb_num_set(sdb, "version", dw->encoding.version, 0);

	TRY_SAVE_SECTION("debug_aranges", dw->aranges);
	TRY_SAVE_SECTION("debug_abbrev", dw->abbrev);
	TRY_SAVE_SECTION("debug_info", dw->info);
	TRY_SAVE_SECTION("debug_str", dw->str);
	TRY_SAVE_SECTION("debug_addr", dw->addr);
	TRY_SAVE_SECTION("debug_line", dw->line);
	if (dw->loc) {
		save_section("debug_loc", dw->loc->debug_loc, sdb);
		save_section("debug_loclists", dw->loc->debug_loclists, sdb);
	}
	if (dw->rng) {
		save_section("debug_ranges", dw->rng->debug_ranges, sdb);
		save_section("debug_rnglists", dw->rng->debug_rnglists, sdb);
	}
	return true;
}

#define TRY_LOAD_SECTION(name, X, F) \
	do { \
		RzBuffer *buf = load_section(name, sdb); \
		if (buf) { \
			(X) = (F); \
		} \
	} while (0)

RZ_API bool rz_bin_dwarf_deserialize_sdb(RzBinDWARF *dw, Sdb *sdb) {
	rz_return_val_if_fail(dw, false);
	dw->encoding.big_endian = sdb_bool_get(sdb, "big_endian", 0);
	dw->encoding.is_64bit = sdb_bool_get(sdb, "is_64bit", 0);
	dw->encoding.address_size = sdb_num_get(sdb, "address_size", 0);
	dw->encoding.version = sdb_num_get(sdb, "version", 0);

	TRY_LOAD_SECTION("debug_aranges", dw->aranges, rz_bin_dwarf_aranges_from_buf(buf, dw->encoding.big_endian));
	TRY_LOAD_SECTION("debug_abbrev", dw->abbrev, rz_bin_dwarf_abbrev_from_buf(buf));
	TRY_LOAD_SECTION("debug_str", dw->str, rz_bin_dwarf_str_from_buf(buf));
	TRY_LOAD_SECTION("debug_addr", dw->addr, DebugAddr_from_buf(buf));
	if (dw->abbrev) {
		TRY_LOAD_SECTION("debug_info", dw->info, rz_bin_dwarf_info_from_buf(buf, dw->encoding.big_endian, dw->abbrev, dw->str));
	}
	TRY_LOAD_SECTION("debug_line", dw->line,
		rz_bin_dwarf_line_from_buf(buf, &dw->encoding, dw->info, RZ_BIN_DWARF_LINE_INFO_MASK_LINES_ALL));

	RzBuffer *loc = load_section("debug_loc", sdb);
	RzBuffer *loclists = load_section("debug_loclists", sdb);
	if (loc || loclists) {
		dw->loc = rz_bin_dwarf_loclists_new_from_buf(loc, loclists, dw->addr);
	}

	RzBuffer *ranges = load_section("debug_ranges", sdb);
	RzBuffer *rnglists = load_section("debug_rnglists", sdb);
	if (ranges || rnglists) {
		dw->rng = rz_bin_dwarf_rnglists_new_from_buf(ranges, rnglists, dw->addr);
	}
	return true;
}
