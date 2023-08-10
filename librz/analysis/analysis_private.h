// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_ANALYSIS_PRIVATE_H
#define RZ_ANALYSIS_PRIVATE_H

#include <rz_analysis.h>

RZ_IPI RZ_BORROW RzAnalysisVar *rz_analysis_function_add_var(
	RzAnalysisFunction *fcn, RZ_OWN RzAnalysisVar *var);

#endif // RZ_ANALYSIS_PRIVATE_H
