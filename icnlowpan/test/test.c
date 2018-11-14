/*
 * Copyright (C) 2018 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <string.h>
#include "unity.h"
#include "icnlowpan.h"

#ifdef MODULE_NDNLOWPAN
#include "ndnlowpan.h"
#endif

#if 0

static const uint8_t ndn_int_01[] = {
    0x05, 0x14, 0x07, 0x08, 0x08, 0x03, 0x48, 0x41,
    0x57, 0x08, 0x01, 0x41, 0x0a, 0x04, 0x12, 0x57,
    0x05, 0x00, 0x0c, 0x02, 0x03, 0xe8
};
static const uint8_t ndn_int_disp_01[] = {
    0xF2, ICNL_DISPATCH_NDN_INT, /* Page 2 and LOWPAN_NDN_INT */
    0x05, 0x14, 0x07, 0x08, 0x08, 0x03, 0x48, 0x41,
    0x57, 0x08, 0x01, 0x41, 0x0a, 0x04, 0x12, 0x57,
    0x05, 0x00, 0x0c, 0x02, 0x03, 0xe8
};
static const uint8_t ndn_int_hc_01[] = {
    0xF2, ICNL_DISPATCH_NDN_INT_HC_A, 0x44, /* Page 2 and LOWPAN_NDN_INT_HC_A */
    0x0d, 0x06, 0x03, 0x48, 0x41, 0x57, 0x01, 0x41,
    0x12, 0x57, 0x05, 0x00, 0x03, 0xe8
};

static const uint8_t ndn_int_02[] = {
    0x05, 0x14, 0x07, 0x08, 0x08, 0x03, 0x48, 0x41,
    0x57, 0x08, 0x01, 0x41, 0x0a, 0x04, 0x12, 0x57,
    0x05, 0x00, 0x0c, 0x02, 0x0f, 0xa0
};
static const uint8_t ndn_int_hc_02[] = {
    0xF2, ICNL_DISPATCH_NDN_INT_HC_A, 0x4A, /* Page 2 and LOWPAN_NDN_INT_HC_A */
    0x0B, 0x06, 0x03, 0x48, 0x41, 0x57, 0x01, 0x41,
    0x12, 0x57, 0x05, 0x00
};

static const uint8_t ndn_int_03[] = {
    0x05, 0x18, 0x07, 0x08, 0x08, 0x03, 0x48, 0x41,
    0x57, 0x08, 0x01, 0x41, 0x09, 0x02, 0x12, 0x00,
    0x0a, 0x04, 0xd6, 0x3d, 0xb2, 0x5b, 0x0c, 0x02,
    0x0f, 0xa0
};
static const uint8_t ndn_int_hc_03[] = {
    0xF2, ICNL_DISPATCH_NDN_INT_HC_AB, 0x4A, 0x02, /* Page 2 and LOWPAN_NDN_INT_HC_A */
    0x0b, 0x06, 0x03, 0x48, 0x41, 0x57, 0x01, 0x41,
    0xd6, 0x3d, 0xb2, 0x5b
};

static const uint8_t ndn_data_01[] = {
    0x06, 0x18, 0x07, 0x08, 0x08, 0x03, 0x48, 0x41,
    0x57, 0x08, 0x01, 0x41, 0x14, 0x00, 0x15, 0x01,
    0xaa, 0x16, 0x05, 0x1b, 0x01, 0x00, 0x1c, 0x00,
    0x17, 0x00
};
static const uint8_t ndn_data_disp_01[] = {
    0xF2, ICNL_DISPATCH_NDN_DATA, /* Page 2 and LOWPAN_NDN_DATA */
    0x06, 0x18, 0x07, 0x08, 0x08, 0x03, 0x48, 0x41,
    0x57, 0x08, 0x01, 0x41, 0x14, 0x00, 0x15, 0x01,
    0xaa, 0x16, 0x05, 0x1b, 0x01, 0x00, 0x1c, 0x00,
    0x17, 0x00
};
static const uint8_t ndn_data_hc_01[] = {
    0xF2, ICNL_DISPATCH_NDN_DATA_HC_A, 0x40, /* Page 2 and LOWPAN_NDN_DATA */
    0x0F, 0x06, 0x03, 0x48, 0x41, 0x57, 0x01, 0x41,
    0x01, 0xaa, 0x04, 0x01, 0x00, 0x1c, 0x00, 0x00
};

static const uint8_t ndn_data_02[] = {
    0x06, 0x16, 0x07, 0x08, 0x08, 0x03, 0x48, 0x41,
    0x57, 0x08, 0x01, 0x41, 0x14, 0x00, 0x15, 0x01,
    0xaa, 0x16, 0x03, 0x1b, 0x01, 0x00, 0x17, 0x00
};
static const uint8_t ndn_data_hc_02[] = {
    0xF2, ICNL_DISPATCH_NDN_DATA_HC_A, 0x48, /* Page 2 and LOWPAN_NDN_DATA */
    0x09, 0x06, 0x03, 0x48, 0x41, 0x57, 0x01, 0x41,
    0x01, 0xaa
};

static const uint8_t ndn_data_03[] = {
    0x06, 0x3a, 0x07, 0x08, 0x08, 0x03, 0x48, 0x41,
    0x57, 0x08, 0x01, 0x41, 0x14, 0x00, 0x15, 0x23,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0x16, 0x05, 0x1b, 0x01, 0x00,
    0x1c, 0x00, 0x17, 0x00
};
static const uint8_t ndn_data_hc_03[] = {
    0xF2, ICNL_DISPATCH_NDN_DATA_HC_A, 0x40,
    0x31, 0x06, 0x03, 0x48, 0x41, 0x57, 0x01, 0x41,
    0x23, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0x04, 0x01, 0x00, 0x1c,
    0x00, 0x00
};

static const uint8_t ndn_data_04[] = {
    0x06, 0xfd, 0x01, 0xA9, 0x07, 0x08, 0x08, 0x03,
    0x48, 0x41, 0x57, 0x08, 0x01, 0x41, 0x14, 0x00,
    0x15, 0xfd, 0x01, 0x90, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0x16, 0x05, 0x1b, 0x01,
    0x00, 0x1c, 0x00, 0x17, 0x00
};
static const uint8_t ndn_data_hc_04[] = {
    0xF2, ICNL_DISPATCH_NDN_DATA_HC_A, 0x40,
    0xff, 0xa0, 0x06, 0x03, 0x48, 0x41, 0x57, 0x01,
    0x41, 0xff, 0x91, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0x04, 0x01, 0x00, 0x1c, 0x00,
    0x00
};

static const uint8_t ndn_data_05[] = {
    0x06, 0x1a, 0x07, 0x08, 0x08, 0x03, 0x48, 0x41,
    0x57, 0x08, 0x01, 0x41, 0x14, 0x04, 0x19, 0x02,
    0x27, 0x10, 0x15, 0x01, 0xaa, 0x16, 0x03, 0x1b,
    0x01, 0x00, 0x17, 0x00
};
static const uint8_t ndn_data_hc_05[] = {
    0xF2, ICNL_DISPATCH_NDN_DATA_HC_AB, 0x48, 0x20,
    0x0b, 0x06, 0x03, 0x48, 0x41, 0x57, 0x01, 0x41,
    0x27, 0x10, 0x01, 0xaa
};

static const uint8_t ndn_data_06[] = {
    0x06, 0xfd, 0x01, 0x1A, 0x07, 0x08, 0x08, 0x03,
    0x48, 0x41, 0x57, 0x08, 0x01, 0x41, 0x14, 0x04,
    0x19, 0x02, 0x27, 0x10, 0x15, 0xfd, 0x00, 0xff,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x16,
    0x03, 0x1b, 0x01, 0x00, 0x17, 0x00
};
static const uint8_t ndn_data_hc_06[] = {
    0xf2, 0x99, 0x48, 0x20, 0xff, 0x0B, 0x06, 0x03,
    0x48, 0x41, 0x57, 0x01, 0x41, 0x27, 0x10, 0xff,
    0x00, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41
};
#endif

#ifdef MODULE_NDNLOWPAN
#if 0
void test_encode_ndn(void)
{
    uint8_t out_int[sizeof(ndn_int_01) / sizeof(ndn_int_01[0]) + 2];
    uint8_t out_data[sizeof(ndn_data_01) / sizeof(ndn_data_01[0]) + 2];

    icnl_tlv_off_t pos_int = icnl_encode(out_int, ICNL_PROTO_NDN,
                                         (uint8_t *)ndn_int_01,
                                         sizeof(ndn_int_01)/sizeof(ndn_int_01[0]));

    TEST_ASSERT_EQUAL_UINT(sizeof(ndn_int_01)/sizeof(ndn_int_01[0]) + 2, pos_int);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(ndn_int_01, out_int + 2, pos_int - 2);

    icnl_tlv_off_t pos_data = icnl_encode(out_data, ICNL_PROTO_NDN,
                                          (uint8_t *)ndn_data_01,
                                          sizeof(ndn_data_01)/sizeof(ndn_data_01[0]));

    TEST_ASSERT_EQUAL_UINT(sizeof(ndn_data_01)/sizeof(ndn_data_01[0]) + 2, pos_data);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(ndn_data_01, out_data + 2, pos_data - 2);
}

void test_encode_ndn_int_hc_01(void)
{
    uint8_t out_int[sizeof(ndn_int_01) / sizeof(ndn_int_01[0]) + 16];

    icnl_tlv_off_t pos_int = icnl_encode(out_int, ICNL_PROTO_NDN_HC,
                                         (uint8_t *)ndn_int_01,
                                         sizeof(ndn_int_01)/sizeof(ndn_int_01[0]));

    TEST_ASSERT_EQUAL_UINT(sizeof(ndn_int_hc_01)/sizeof(ndn_int_hc_01[0]), pos_int);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(ndn_int_hc_01, out_int, pos_int);
}

void test_encode_ndn_int_hc_02(void)
{
    uint8_t out_int[sizeof(ndn_int_02) / sizeof(ndn_int_02[0]) + 16];

    icnl_tlv_off_t pos_int = icnl_encode(out_int, ICNL_PROTO_NDN_HC,
                                         (uint8_t *)ndn_int_02,
                                         sizeof(ndn_int_02)/sizeof(ndn_int_02[0]));

    TEST_ASSERT_EQUAL_UINT(sizeof(ndn_int_hc_02)/sizeof(ndn_int_hc_02[0]), pos_int);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(ndn_int_hc_02, out_int, pos_int);
}

void test_encode_ndn_int_hc_03(void)
{
    uint8_t out_int[sizeof(ndn_int_03) / sizeof(ndn_int_03[0]) + 16];

    icnl_tlv_off_t pos_int = icnl_encode(out_int, ICNL_PROTO_NDN_HC,
                                         (uint8_t *)ndn_int_03,
                                         sizeof(ndn_int_03)/sizeof(ndn_int_03[0]));

    TEST_ASSERT_EQUAL_UINT(sizeof(ndn_int_hc_03)/sizeof(ndn_int_hc_03[0]), pos_int);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(ndn_int_hc_03, out_int, pos_int);
}

void test_encode_ndn_data_hc_01(void)
{
    uint8_t out_data[sizeof(ndn_data_01) / sizeof(ndn_data_01[0]) + 16];

    icnl_tlv_off_t pos_data = icnl_encode(out_data, ICNL_PROTO_NDN_HC,
                                          (uint8_t *)ndn_data_01,
                                          sizeof(ndn_data_01)/sizeof(ndn_data_01[0]));

    TEST_ASSERT_EQUAL_UINT(sizeof(ndn_data_hc_01)/sizeof(ndn_data_hc_01[0]), pos_data);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(ndn_data_hc_01, out_data, pos_data);
}

void test_encode_ndn_data_hc_02(void)
{
    uint8_t out_data[sizeof(ndn_data_02) / sizeof(ndn_data_02[0]) + 16];

    icnl_tlv_off_t pos_data = icnl_encode(out_data, ICNL_PROTO_NDN_HC,
                                          (uint8_t *)ndn_data_02,
                                          sizeof(ndn_data_02)/sizeof(ndn_data_02[0]));

    TEST_ASSERT_EQUAL_UINT(sizeof(ndn_data_hc_02)/sizeof(ndn_data_hc_02[0]), pos_data);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(ndn_data_hc_02, out_data, pos_data);
}

void test_encode_ndn_data_hc_03(void)
{
    uint8_t out_data[sizeof(ndn_data_03) / sizeof(ndn_data_03[0]) + 16];

    icnl_tlv_off_t pos_data = icnl_encode(out_data, ICNL_PROTO_NDN_HC,
                                          (uint8_t *)ndn_data_03,
                                          sizeof(ndn_data_03)/sizeof(ndn_data_03[0]));

    TEST_ASSERT_EQUAL_UINT(sizeof(ndn_data_hc_03)/sizeof(ndn_data_hc_03[0]), pos_data);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(ndn_data_hc_03, out_data, pos_data);
}

void test_encode_ndn_data_hc_04(void)
{
    uint8_t out_data[sizeof(ndn_data_04) / sizeof(ndn_data_04[0]) + 16];

    icnl_tlv_off_t pos_data = icnl_encode(out_data, ICNL_PROTO_NDN_HC,
                                          (uint8_t *)ndn_data_04,
                                          sizeof(ndn_data_04)/sizeof(ndn_data_04[0]));

    TEST_ASSERT_EQUAL_UINT(sizeof(ndn_data_hc_04)/sizeof(ndn_data_hc_04[0]), pos_data);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(ndn_data_hc_04, out_data, pos_data);
}

void test_encode_ndn_data_hc_05(void)
{
    uint8_t out_data[sizeof(ndn_data_05) / sizeof(ndn_data_05[0]) + 16];

    icnl_tlv_off_t pos_data = icnl_encode(out_data, ICNL_PROTO_NDN_HC,
                                          (uint8_t *)ndn_data_05,
                                          sizeof(ndn_data_05)/sizeof(ndn_data_05[0]));

    TEST_ASSERT_EQUAL_UINT(sizeof(ndn_data_hc_05)/sizeof(ndn_data_hc_05[0]), pos_data);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(ndn_data_hc_05, out_data, pos_data);
}

void test_encode_ndn_data_hc_06(void)
{
    uint8_t out_data[sizeof(ndn_data_06) / sizeof(ndn_data_06[0]) + 16];

    icnl_tlv_off_t pos_data = icnl_encode(out_data, ICNL_PROTO_NDN_HC,
                                          (uint8_t *)ndn_data_06,
                                          sizeof(ndn_data_06)/sizeof(ndn_data_06[0]));

    TEST_ASSERT_EQUAL_UINT(sizeof(ndn_data_hc_06)/sizeof(ndn_data_hc_06[0]), pos_data);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(ndn_data_hc_06, out_data, pos_data);
}

void test_decode_ndn(void)
{
    uint8_t out_int[sizeof(ndn_int_01)/sizeof(ndn_int_01[0])];
    uint8_t out_data[sizeof(ndn_data_01)/sizeof(ndn_data_01[0])];

    icnl_tlv_off_t pos_int = icnl_decode(out_int, (uint8_t *)ndn_int_disp_01,
                                         sizeof(ndn_int_disp_01)/sizeof(ndn_int_disp_01[0]), NULL);

    TEST_ASSERT_EQUAL_UINT(sizeof(ndn_int_01)/sizeof(ndn_int_01[0]), pos_int);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(ndn_int_01, out_int, pos_int);

    icnl_tlv_off_t pos_data = icnl_decode(out_data, (uint8_t *)ndn_data_disp_01,
                                          sizeof(ndn_data_disp_01)/sizeof(ndn_data_disp_01[0]), NULL);

    TEST_ASSERT_EQUAL_UINT(sizeof(ndn_data_01)/sizeof(ndn_data_01[0]), pos_data);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(ndn_data_01, out_data, pos_data);
}

void test_decode_ndn_int_hc_01(void)
{
    uint8_t out_int[sizeof(ndn_int_01) / sizeof(ndn_int_01[0]) + 16];

    icnl_tlv_off_t pos_int = icnl_decode(out_int, (uint8_t *)ndn_int_hc_01,
                                         sizeof(ndn_int_hc_01)/sizeof(ndn_int_hc_01[0]), NULL);

    TEST_ASSERT_EQUAL_UINT(sizeof(ndn_int_01)/sizeof(ndn_int_01[0]), pos_int);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(ndn_int_01, out_int, pos_int);
}

void test_decode_ndn_int_hc_02(void)
{
    uint8_t out_int[sizeof(ndn_int_02) / sizeof(ndn_int_02[0]) + 16];

    icnl_tlv_off_t pos_int = icnl_decode(out_int, (uint8_t *)ndn_int_hc_02,
                                         sizeof(ndn_int_hc_02)/sizeof(ndn_int_hc_02[0]), NULL);

    TEST_ASSERT_EQUAL_UINT(sizeof(ndn_int_02)/sizeof(ndn_int_02[0]), pos_int);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(ndn_int_02, out_int, pos_int);
}

void test_decode_ndn_int_hc_03(void)
{
    uint8_t out_int[sizeof(ndn_int_03) / sizeof(ndn_int_03[0]) + 16];

    icnl_tlv_off_t pos_int = icnl_decode(out_int, (uint8_t *)ndn_int_hc_03,
                                         sizeof(ndn_int_hc_03)/sizeof(ndn_int_hc_03[0]), NULL);

    TEST_ASSERT_EQUAL_UINT(sizeof(ndn_int_03)/sizeof(ndn_int_03[0]), pos_int);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(ndn_int_03, out_int, pos_int);
}

void test_decode_ndn_data_hc_01(void)
{
    uint8_t out_data[sizeof(ndn_data_01) / sizeof(ndn_data_01[0]) + 16];

    icnl_tlv_off_t pos_data = icnl_decode(out_data, (uint8_t *)ndn_data_hc_01,
                                         sizeof(ndn_data_hc_01)/sizeof(ndn_data_hc_01[0]), NULL);

    TEST_ASSERT_EQUAL_UINT(sizeof(ndn_data_01)/sizeof(ndn_data_01[0]), pos_data);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(ndn_data_01, out_data, pos_data);
}

void test_decode_ndn_data_hc_02(void)
{
    uint8_t out_data[sizeof(ndn_data_02) / sizeof(ndn_data_02[0]) + 16];

    icnl_tlv_off_t pos_data = icnl_decode(out_data, (uint8_t *)ndn_data_hc_02,
                                         sizeof(ndn_data_hc_02)/sizeof(ndn_data_hc_02[0]), NULL);

    TEST_ASSERT_EQUAL_UINT(sizeof(ndn_data_02)/sizeof(ndn_data_02[0]), pos_data);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(ndn_data_02, out_data, pos_data);
}

void test_decode_ndn_data_hc_03(void)
{
    uint8_t out_data[sizeof(ndn_data_03) / sizeof(ndn_data_03[0]) + 16];

    icnl_tlv_off_t pos_data = icnl_decode(out_data, (uint8_t *)ndn_data_hc_03,
                                         sizeof(ndn_data_hc_03)/sizeof(ndn_data_hc_03[0]), NULL);

    TEST_ASSERT_EQUAL_UINT(sizeof(ndn_data_03)/sizeof(ndn_data_03[0]), pos_data);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(ndn_data_03, out_data, pos_data);
}

void test_decode_ndn_data_hc_04(void)
{
    uint8_t out_data[sizeof(ndn_data_04) / sizeof(ndn_data_04[0]) + 16];

    icnl_tlv_off_t pos_data = icnl_decode(out_data, (uint8_t *)ndn_data_hc_04,
                                         sizeof(ndn_data_hc_04)/sizeof(ndn_data_hc_04[0]), NULL);

    TEST_ASSERT_EQUAL_UINT(sizeof(ndn_data_04)/sizeof(ndn_data_04[0]), pos_data);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(ndn_data_04, out_data, pos_data);
}

void test_decode_ndn_data_hc_05(void)
{
    uint8_t out_data[sizeof(ndn_data_05) / sizeof(ndn_data_05[0]) + 16];

    icnl_tlv_off_t pos_data = icnl_decode(out_data, (uint8_t *)ndn_data_hc_05,
                                         sizeof(ndn_data_hc_05)/sizeof(ndn_data_hc_05[0]), NULL);

    TEST_ASSERT_EQUAL_UINT(sizeof(ndn_data_05)/sizeof(ndn_data_05[0]), pos_data);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(ndn_data_05, out_data, pos_data);
}

void test_decode_ndn_data_hc_06(void)
{
    uint8_t out_data[sizeof(ndn_data_06) / sizeof(ndn_data_06[0]) + 16];

    icnl_tlv_off_t pos_data = icnl_decode(out_data, (uint8_t *)ndn_data_hc_06,
                                         sizeof(ndn_data_hc_06)/sizeof(ndn_data_hc_06[0]), NULL);

    TEST_ASSERT_EQUAL_UINT(sizeof(ndn_data_06)/sizeof(ndn_data_06[0]), pos_data);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(ndn_data_06, out_data, pos_data);
}
#endif

static const uint8_t ndn03_int_01[] = {
    0x05, 0x10, 0x07, 0x08, 0x08, 0x03, 0x48, 0x41,
    0x57, 0x08, 0x01, 0x41, 0x0a, 0x04, 0x12, 0x57,
    0x05, 0x00
};
static const uint8_t ndn03_int_hc_01a[] = {
    0xF2, 0x80, 0x0A, 0x31, 0x48, 0x41, 0x57, 0x41,
    0x00, 0x12, 0x57, 0x05, 0x00
};
static const uint8_t ndn03_int_hc_01b[] = {
    0xF2, 0xA0, 0xC2, 0x80, 0x01, 0x0A, 0x31, 0x48,
    0x41, 0x57, 0x41, 0x00, 0x12, 0x57, 0x05, 0x00
};
static const uint8_t ndn03_int_hc_01c[] = {
    0xF2, 0xA0, 0xC2, 0x05, 0x06, 0x10, 0x41, 0x12,
    0x57, 0x05, 0x00
};

static const uint8_t ndn03_int_02[] = {
    0x05, 0x0D, 0x07, 0x05, 0x08, 0x03, 0x48, 0x41,
    0x57, 0x0a, 0x04, 0x12, 0x57, 0x05, 0x00
};
static const uint8_t ndn03_int_hc_02[] = {
    0xF2, 0x80, 0x08, 0x30, 0x48, 0x41, 0x57, 0x12,
    0x57, 0x05, 0x00
};

static const uint8_t ndn03_data_01[] = {
    0x06, 0x14, 0x07, 0x08, 0x08, 0x03, 0x48, 0x41,
    0x57, 0x08, 0x01, 0x41, 0x15, 0x01, 0xAA, 0x16,
    0x03, 0x1b, 0x01, 0x00, 0x17, 0x00
};
static const uint8_t ndn03_data_hc_01a[] = {
    0xF2, 0xC0, 0x0D, 0x31, 0x48, 0x41, 0x57, 0x41,
    0x00, 0x01, 0xAA, 0x03, 0x1b, 0x01, 0x00, 0x00
};
static const uint8_t ndn03_data_hc_01b[] = {
    0xF2, 0xE0, 0xC2, 0x80, 0x01, 0x09, 0x10, 0x41,
    0x01, 0xAA, 0x03, 0x1b, 0x01, 0x00, 0x00
};

static const uint8_t cids[] = { 0x42, 0x00, 0x01 };
static const uint8_t cids2[] = { 0xC2, 0x05 };

void test_cb_hopid(uint8_t hop_id)
{
    TEST_ASSERT_EQUAL_UINT8(cids[0], hop_id);
}

unsigned test_cb_hopid_skip_prefix(uint8_t hop_id, void *context)
{
    (void) context;
    TEST_ASSERT_EQUAL_UINT8(cids[0], hop_id);
    return 5;
}

unsigned test_cb_context_skip_prefix(uint8_t cid, void *context)
{
    (void) context;
    TEST_ASSERT_EQUAL_UINT8(cids2[1], cid);
    return 5;
}

unsigned test_cb_hopid_decompress_name(uint8_t *out, uint8_t hop_id, void *context)
{
    (void) context;
    const char name[] = { 0x08, 0x03, 0x48, 0x41, 0x57, 0x00 };
    unsigned name_len = strlen(name);

    TEST_ASSERT_EQUAL_UINT8(cids[0], hop_id);

    memcpy(out, name, name_len);

    return name_len;
}

unsigned test_cb_context_decompress_name(uint8_t *out, uint8_t prefix_cid, void *context)
{
    (void) context;
    const char name[] = { 0x08, 0x03, 0x48, 0x41, 0x57, 0x00 };
    unsigned name_len = strlen(name);

    TEST_ASSERT_EQUAL_UINT8(cids2[1], prefix_cid);

    memcpy(out, name, name_len);

    return name_len;
}

void test_ndn03_int_hc_01a(void)
{
    uint8_t out[sizeof(ndn03_int_01) / sizeof(ndn03_int_01[0]) + 16];
    icnl_tlv_off_t pos;

    pos = icnl_encode(out, ICNL_PROTO_NDN_HC,
                      (uint8_t *)ndn03_int_01,
                      sizeof(ndn03_int_01)/sizeof(ndn03_int_01[0]),
                      NULL, 0, NULL);

    TEST_ASSERT_EQUAL_UINT(sizeof(ndn03_int_hc_01a)/sizeof(ndn03_int_hc_01a[0]), pos);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(ndn03_int_hc_01a, out, pos);

    pos = icnl_decode(out, (uint8_t *)ndn03_int_hc_01a,
                      sizeof(ndn03_int_hc_01a)/sizeof(ndn03_int_hc_01a[0]), NULL);

    TEST_ASSERT_EQUAL_UINT(sizeof(ndn03_int_01)/sizeof(ndn03_int_01[0]), pos);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(ndn03_int_01, out, pos);
}

void test_ndn03_int_hc_01b(void)
{
    uint8_t out[sizeof(ndn03_int_01) / sizeof(ndn03_int_01[0]) + 16];
    icnl_tlv_off_t pos;

    icnl_cb_hopid = test_cb_hopid;

    pos = icnl_encode(out, ICNL_PROTO_NDN_HC,
                      (uint8_t *)ndn03_int_01,
                      sizeof(ndn03_int_01)/sizeof(ndn03_int_01[0]),
                      (uint8_t *)cids, sizeof(cids)/sizeof(cids[0]), NULL);

    TEST_ASSERT_EQUAL_UINT(sizeof(ndn03_int_hc_01b)/sizeof(ndn03_int_hc_01b[0]), pos);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(ndn03_int_hc_01b, out, pos);

    pos = icnl_decode(out, (uint8_t *)ndn03_int_hc_01b,
                      sizeof(ndn03_int_hc_01b)/sizeof(ndn03_int_hc_01b[0]), NULL);

    TEST_ASSERT_EQUAL_UINT(sizeof(ndn03_int_01)/sizeof(ndn03_int_01[0]), pos);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(ndn03_int_01, out, pos);
}

void test_ndn03_int_hc_01c(void)
{
    uint8_t out[sizeof(ndn03_int_01) / sizeof(ndn03_int_01[0]) + 16];
    icnl_tlv_off_t pos;

    icnl_cb_context_skip_prefix = test_cb_context_skip_prefix;
    icnl_cb_context_decompress_name = test_cb_context_decompress_name;

    pos = icnl_encode(out, ICNL_PROTO_NDN_HC,
                      (uint8_t *)ndn03_int_01,
                      sizeof(ndn03_int_01)/sizeof(ndn03_int_01[0]),
                      (uint8_t *)cids2, sizeof(cids2)/sizeof(cids2[0]), NULL);

    TEST_ASSERT_EQUAL_UINT(sizeof(ndn03_int_hc_01c)/sizeof(ndn03_int_hc_01c[0]), pos);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(ndn03_int_hc_01c, out, pos);

    pos = icnl_decode(out, (uint8_t *)ndn03_int_hc_01c,
                      sizeof(ndn03_int_hc_01c)/sizeof(ndn03_int_hc_01c[0]), NULL);

    TEST_ASSERT_EQUAL_UINT(sizeof(ndn03_int_01)/sizeof(ndn03_int_01[0]), pos);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(ndn03_int_01, out, pos);
}

void test_ndn03_int_hc_02(void)
{
    uint8_t out[sizeof(ndn03_int_02) / sizeof(ndn03_int_02[0]) + 16];
    icnl_tlv_off_t pos;

    pos = icnl_encode(out, ICNL_PROTO_NDN_HC,
                      (uint8_t *)ndn03_int_02,
                      sizeof(ndn03_int_02)/sizeof(ndn03_int_02[0]),
                      NULL, 0, NULL);

    TEST_ASSERT_EQUAL_UINT(sizeof(ndn03_int_hc_02)/sizeof(ndn03_int_hc_02[0]), pos);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(ndn03_int_hc_02, out, pos);

    pos = icnl_decode(out, (uint8_t *)ndn03_int_hc_02,
                      sizeof(ndn03_int_hc_02)/sizeof(ndn03_int_hc_02[0]), NULL);

    TEST_ASSERT_EQUAL_UINT(sizeof(ndn03_int_02)/sizeof(ndn03_int_02[0]), pos);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(ndn03_int_02, out, pos);
}

void test_ndn03_data_hc_01a(void)
{
    uint8_t out[sizeof(ndn03_data_01) / sizeof(ndn03_data_01[0]) + 16];
    icnl_tlv_off_t pos;

    pos = icnl_encode(out, ICNL_PROTO_NDN_HC,
                      (uint8_t *)ndn03_data_01,
                      sizeof(ndn03_data_01)/sizeof(ndn03_data_01[0]),
                      NULL, 0, NULL);

    TEST_ASSERT_EQUAL_UINT(sizeof(ndn03_data_hc_01a)/sizeof(ndn03_data_hc_01a[0]), pos);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(ndn03_data_hc_01a, out, pos);

    pos = icnl_decode(out, (uint8_t *)ndn03_data_hc_01a,
                      sizeof(ndn03_data_hc_01a)/sizeof(ndn03_data_hc_01a[0]), NULL);

    TEST_ASSERT_EQUAL_UINT(sizeof(ndn03_data_01)/sizeof(ndn03_data_01[0]), pos);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(ndn03_data_01, out, pos);
}

void test_ndn03_data_hc_01b(void)
{
    uint8_t out[sizeof(ndn03_data_01) / sizeof(ndn03_data_01[0]) + 16];
    icnl_tlv_off_t pos;

    icnl_cb_hopid_skip_prefix = test_cb_hopid_skip_prefix;
    icnl_cb_hopid_decompress_name = test_cb_hopid_decompress_name;

    pos = icnl_encode(out, ICNL_PROTO_NDN_HC,
                      (uint8_t *)ndn03_data_01,
                      sizeof(ndn03_data_01)/sizeof(ndn03_data_01[0]),
                      (uint8_t *)cids, sizeof(cids)/sizeof(cids[0]), NULL);

    TEST_ASSERT_EQUAL_UINT(sizeof(ndn03_data_hc_01b)/sizeof(ndn03_data_hc_01b[0]), pos);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(ndn03_data_hc_01b, out, pos);

    pos = icnl_decode(out, (uint8_t *)ndn03_data_hc_01b,
                      sizeof(ndn03_data_hc_01b)/sizeof(ndn03_data_hc_01b[0]), NULL);

    TEST_ASSERT_EQUAL_UINT(sizeof(ndn03_data_01)/sizeof(ndn03_data_01[0]), pos);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(ndn03_data_01, out, pos);
}

#endif
 
int main(void)
{
    UNITY_BEGIN();
 
#ifdef MODULE_NDNLOWPAN
#if 0
    RUN_TEST(test_encode_ndn);
    RUN_TEST(test_encode_ndn_int_hc_01);
    RUN_TEST(test_encode_ndn_int_hc_02);
    RUN_TEST(test_encode_ndn_int_hc_03);
    RUN_TEST(test_encode_ndn_data_hc_01);
    RUN_TEST(test_encode_ndn_data_hc_02);
    RUN_TEST(test_encode_ndn_data_hc_03);
    RUN_TEST(test_encode_ndn_data_hc_04);
    RUN_TEST(test_encode_ndn_data_hc_05);
    RUN_TEST(test_encode_ndn_data_hc_06);
    RUN_TEST(test_decode_ndn);
    RUN_TEST(test_decode_ndn_int_hc_01);
    RUN_TEST(test_decode_ndn_int_hc_02);
    RUN_TEST(test_decode_ndn_int_hc_03);
    RUN_TEST(test_decode_ndn_data_hc_01);
    RUN_TEST(test_decode_ndn_data_hc_02);
    RUN_TEST(test_decode_ndn_data_hc_03);
    RUN_TEST(test_decode_ndn_data_hc_04);
    RUN_TEST(test_decode_ndn_data_hc_05);
    RUN_TEST(test_decode_ndn_data_hc_06);
#endif
    RUN_TEST(test_ndn03_int_hc_01a);
    RUN_TEST(test_ndn03_int_hc_01b);
    RUN_TEST(test_ndn03_int_hc_01c);
    RUN_TEST(test_ndn03_int_hc_02);

    RUN_TEST(test_ndn03_data_hc_01a);
    RUN_TEST(test_ndn03_data_hc_01b);
#endif
 
    return UNITY_END();
}
