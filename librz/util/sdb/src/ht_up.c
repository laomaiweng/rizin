// SPDX-FileCopyrightText: 2016-2018 crowell
// SPDX-FileCopyrightText: 2016-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2016-2018 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: BSD-3-Clause

#include "ht_up.h"
#include "ht_inc.c"

static HtName_(Ht) * internal_ht_default_new(ut32 size, ut32 prime_idx, HT_(DupValue) valdup, HT_(KvFreeFunc) pair_free, HT_(CalcSizeV) calcsizeV) {
	HT_(Options)
	opt = {
		.cmp = NULL,
		.hashfn = NULL, // TODO: use a better hash function for numbers
		.dupkey = NULL,
		.dupvalue = valdup,
		.calcsizeK = NULL,
		.calcsizeV = calcsizeV,
		.freefn = pair_free,
		.elem_size = sizeof(HT_(Kv)),
	};
	return internal_ht_new(size, prime_idx, &opt);
}

RZ_API HtName_(Ht) * Ht_(new)(HT_(DupValue) valdup, HT_(KvFreeFunc) pair_free, HT_(CalcSizeV) calcsizeV) {
	return internal_ht_default_new(ht_primes_sizes[0], 0, valdup, pair_free, calcsizeV);
}

// creates a default HtUP that does not dup, nor free the values
RZ_API HtName_(Ht) * Ht_(new0)(void) {
	return Ht_(new)(NULL, NULL, NULL);
}

RZ_API HtName_(Ht) * Ht_(new_size)(ut32 initial_size, HT_(DupValue) valdup, HT_(KvFreeFunc) pair_free, HT_(CalcSizeV) calcsizeV) {
	ut32 i = 0;

	while (i < S_ARRAY_SIZE(ht_primes_sizes) &&
		ht_primes_sizes[i] * LOAD_FACTOR < initial_size) {
		i++;
	}
	if (i == S_ARRAY_SIZE(ht_primes_sizes)) {
		i = UT32_MAX;
	}

	ut32 sz = compute_size(i, (ut32)(initial_size * (2 - LOAD_FACTOR)));
	return internal_ht_default_new(sz, i, valdup, pair_free, calcsizeV);
}
