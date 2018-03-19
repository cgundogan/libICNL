/*
 * Copyright (C) 2018 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdio.h>
#include <string.h>

#include "ndnlowpan.h"

icnl_tlv_off_t icnl_ndn_decode_interest(uint8_t *out, const uint8_t *in,
                                        icnl_tlv_off_t in_len)
{
    memcpy(out, in, in_len);

    return in_len;
}

icnl_tlv_off_t icnl_ndn_decode_name(uint8_t *out, const uint8_t *in,
                                    icnl_tlv_off_t *pos_in, const uint8_t *a)
{
    icnl_tlv_off_t pos_out = 0, name_len;
    uint8_t out_total_name_len = 0;
    uint8_t *name_length;

    out[pos_out++] = ICNL_NDN_TLV_NAME;

    name_len = icnl_ndn_tlv_hc_read(in, pos_in);
    name_length = out + (pos_out++);
    /* skip maximum amount of possible length field size */
    pos_out += 8;

    if ((*a & 0xC0) == 0) {
        memcpy(out + pos_out, in + *pos_in, name_len);
        *pos_in += name_len;
        pos_out += name_len;
    }
    else {
        uint8_t component_type = 0x00;

        if (*a & 0x40) {
            component_type = ICNL_NDN_TLV_GENERIC_NAME_COMPONENT;
        }
        else if (*a & 0x80) {
            component_type = ICNL_NDN_TLV_IMPLICIT_SHA256_DIGEST_COMPONENT;
        }

        if (name_len == 0x00) {
            // whole global prefix
            ICNL_DBG("name_len == 0x00\n");
            memcpy(out + pos_out, hawpfx, glob_pfx_len);
            out_total_name_len = glob_pfx_len;
            pos_out += glob_pfx_len;
        }
        else {
            if(state_compressed) {
                ICNL_DBG("fraction has been compressed\n");
                memcpy(out + pos_out, hawpfx, glob_pfx_len);
                out_total_name_len = glob_pfx_len;
                pos_out += glob_pfx_len;
            }

            icnl_tlv_off_t offset = *pos_in + name_len;
            while (*pos_in < offset) {
                out[pos_out++] = component_type;
                out_total_name_len += 1;
                uint8_t comp_len = in[*pos_in] + 1;
                memcpy(out + pos_out, in + *pos_in, comp_len);
                pos_out += comp_len;
                *pos_in += comp_len;
                out_total_name_len += comp_len;
            }
        }
    }

    icnl_tlv_off_t tmp = 0;
    icnl_ndn_tlv_write(out_total_name_len, name_length, &tmp);
    memmove(name_length + tmp, name_length + 9, pos_out);
    pos_out -= 9 - tmp;

    return pos_out;
}

icnl_tlv_off_t icnl_ndn_decode_nonce(uint8_t *out, const uint8_t *in,
                                     icnl_tlv_off_t *pos_in, const uint8_t *a)
{
    icnl_tlv_off_t pos_out = 0, nonce_len = 4;

    if ((*a & 0x30) == 0x10) {
        nonce_len = 1;
    }
    else if ((*a & 0x30) == 0x20) {
        nonce_len = 2;
    }

    out[pos_out++] = ICNL_NDN_TLV_NONCE;
    out[pos_out++] = 4;

    memset(out + pos_out, 0, 4);
    memcpy(out + pos_out + 4 - nonce_len, in + *pos_in, nonce_len);
    *pos_in += 4;
    pos_out += 4;

    return pos_out;
}

icnl_tlv_off_t icnl_ndn_decode_interest_lifetime(uint8_t *out, const uint8_t *in,
                                                 icnl_tlv_off_t *pos_in,
                                                 const uint8_t *a)
{
    icnl_tlv_off_t pos_out = 0, length = 0;

    if ((*a & 0x0E) == 0x00) {
        return pos_out;
    }
    else {
        out[pos_out++] = ICNL_NDN_TLV_INTEREST_LIFETIME;
        if ((*a & 0x0E) == 0x02) {
            length = 1;
        }
        else if ((*a & 0x0E) == 0x04) {
            length = 2;
        }
        else if ((*a & 0x0E) == 0x06) {
            length = 4;
        }
        else if ((*a & 0x0E) == 0x08) {
            length = 8;
        }
        else if ((*a & 0x0E) == 0x0A) {
            out[pos_out++] = 2;
            /* default value of 4000 ms */
            out[pos_out++] = 0x0F;
            out[pos_out++] = 0xA0;
            return pos_out;
        }

        icnl_ndn_tlv_write(length, out, &pos_out);
        memcpy(out + pos_out, in + *pos_in, length);
        *pos_in += length;
        pos_out += length;
    }

    return pos_out;
}

icnl_tlv_off_t icnl_ndn_decode_selectors(uint8_t *out, const uint8_t *in,
                                         icnl_tlv_off_t *pos_in,
                                         const uint8_t *b)
{
    (void) in;
    (void) pos_in;

    icnl_tlv_off_t pos_out = 0, length = 0;
    uint8_t *out_tlv_len;

    if (!b) {
        return pos_out;
    }

    out[pos_out++] = ICNL_NDN_TLV_SELECTORS;

    out_tlv_len = out + (pos_out++);

    if ((*b & 0x02)) {
        out[pos_out++] = ICNL_NDN_TLV_MUST_BE_FRESH;
        icnl_ndn_tlv_write(0, out, &pos_out);
        length += 2;
    }

    *out_tlv_len = length;

    return pos_out;
}

icnl_tlv_off_t icnl_ndn_decode_meta_info(uint8_t *out, const uint8_t *in,
                                         icnl_tlv_off_t *pos_in, const uint8_t *b)
{
    icnl_tlv_off_t pos_out = 0, tmp;
    uint8_t *out_tlv_len, tmp_b;

    out[pos_out++] = ICNL_NDN_TLV_META_INFO;
    out_tlv_len = out + (pos_out++);

    tmp = pos_out;

    if (b == NULL) {
        *out_tlv_len = 0;
        return pos_out;
    }

    /* ContentType not implemented yet */

    if (*b & 0x70) {
        unsigned len = 0;
        tmp_b = *b & 0x70;

        if (tmp_b == 0x10) {
            len += 1;
        }
        else if (tmp_b == 0x20) {
            len += 2;
        }
        else if (tmp_b == 0x30) {
            len += 4;
        }
        else if (tmp_b == 0x40) {
            len += 8;
        }

        out[pos_out++] = ICNL_NDN_TLV_FRESHNESS_PERIOD;
        out[pos_out++] = len;

        memcpy(out + pos_out, in + *pos_in, len);
        pos_out += len;
        *pos_in += len;
    }

    /* FinalBlockID not implemented yet */

    icnl_tlv_off_t t = 0;
    icnl_ndn_tlv_write(pos_out - tmp, out_tlv_len, &t);

    return pos_out;
}

icnl_tlv_off_t icnl_ndn_decode_content(uint8_t *out, const uint8_t *in,
                                       icnl_tlv_off_t *pos_in, const uint8_t *a)
{
    (void) a;
    icnl_tlv_off_t pos_out = 0, len;

    len = icnl_ndn_tlv_hc_read(in, pos_in);

    out[pos_out++] = ICNL_NDN_TLV_CONTENT;
    icnl_ndn_tlv_write(len, out, &pos_out);

    memcpy(out + pos_out, in + *pos_in, len);
    *pos_in += len;
    pos_out += len;

    return pos_out;
}

icnl_tlv_off_t icnl_ndn_decode_signature_info(uint8_t *out, const uint8_t *in,
                                              icnl_tlv_off_t *pos_in,
                                              const uint8_t *a)
{
    uint8_t mode = *a & 0x38;
    icnl_tlv_off_t pos_out = 0, len = 0;

    if (mode == 0x00){
        len = icnl_ndn_tlv_hc_read(in, pos_in);
        /* include sigtype type */
        len += 1;
        out[pos_out++] = ICNL_NDN_TLV_SIGNATURE_INFO;
        icnl_ndn_tlv_write(len, out, &pos_out);
        out[pos_out++] = ICNL_NDN_TLV_SIGNATURE_TYPE;
        memcpy(out + pos_out, in + *pos_in, len - 1);
        pos_out += len - 1;
        *pos_in += len - 1;
    }
    else if (mode == 0x08) {
        out[pos_out++] = ICNL_NDN_TLV_SIGNATURE_INFO;
        out[pos_out++] = 3;
        out[pos_out++] = ICNL_NDN_TLV_SIGNATURE_TYPE;
        out[pos_out++] = 1;
        out[pos_out++] = 0x00;
    }

    return pos_out;
}

icnl_tlv_off_t icnl_ndn_decode_signature_value(uint8_t *out, const uint8_t *in,
                                               icnl_tlv_off_t *pos_in,
                                               icnl_tlv_off_t in_len,
                                               const uint8_t *a)
{
    uint8_t mode = *a & 0x38;
    icnl_tlv_off_t pos_out = 0, len = 0;

    if (mode == 0x00){
        out[pos_out++] = ICNL_NDN_TLV_SIGNATURE_VALUE;
        len = icnl_ndn_tlv_hc_read(in, pos_in);
        icnl_ndn_tlv_write(len, out, &pos_out);
        memcpy(out + pos_out, in + *pos_in, len);
        pos_out += len;
        *pos_in += len;
    }
    else if (mode == 0x08) {
        out[pos_out++] = ICNL_NDN_TLV_SIGNATURE_VALUE;
        /* workaround for empty sig value in CCN-lite for NDN */
        len = in_len - *pos_in ? 32 : 0;
        out[pos_out++] = len;
    }

    memcpy(out + pos_out, in + *pos_in, len);
    pos_out += len;
    *pos_in += len;

    return pos_out;
}

icnl_tlv_off_t icnl_ndn_decode_interest_hc(uint8_t *out, const uint8_t *in,
                                           icnl_tlv_off_t in_len, uint8_t dispatch)
{
    icnl_tlv_off_t pos_out = 0, pos_in = 0;
    const uint8_t *a, *b = NULL;
    uint8_t *out_packet_length;

    a = in + pos_in++;

    if (dispatch == ICNL_DISPATCH_NDN_INT_HC_AB) {
        b = in + pos_in++;
    }

    out[pos_out++] = ICNL_NDN_TLV_INTEREST;
    out_packet_length = out + (pos_out++);

    /* skip packet length */
    icnl_ndn_tlv_hc_read(in, &pos_in);

    pos_out += icnl_ndn_decode_name(out + pos_out, in, &pos_in, a);
    pos_out += icnl_ndn_decode_selectors(out + pos_out, in, &pos_in, b);
    pos_out += icnl_ndn_decode_nonce(out + pos_out, in, &pos_in, a);
    pos_out += icnl_ndn_decode_interest_lifetime(out + pos_out, in, &pos_in, a);

    memcpy(out + pos_out, in + pos_in, in_len - pos_in);
    pos_out += in_len - pos_in;

    uint8_t tmp[9];
    icnl_tlv_off_t tmp_len = 0;
    icnl_tlv_off_t ll = pos_out - (out_packet_length - out);
    icnl_ndn_tlv_write(ll - 1, tmp, &tmp_len);

    icnl_tlv_off_t skip = tmp_len - 1;

    if (skip) {
        memmove(out_packet_length + skip, out_packet_length, ll);
        pos_out += skip;
    }

    memcpy(out_packet_length, tmp, tmp_len);

    return pos_out;
}

icnl_tlv_off_t icnl_ndn_decode_data_hc(uint8_t *out, const uint8_t *in,
                                       icnl_tlv_off_t in_len, uint8_t dispatch)
{
    icnl_tlv_off_t pos_out = 0, pos_in = 0;
    const uint8_t *a, *b = NULL;
    uint8_t *out_packet_length;

    a = in + pos_in++;
    if (dispatch == ICNL_DISPATCH_NDN_DATA_HC_AB) {
        b = in + pos_in++;
    }

    out[pos_out++] = ICNL_NDN_TLV_DATA;
    out_packet_length = out + (pos_out++);

    /* skip packet length */
    icnl_ndn_tlv_hc_read(in, &pos_in);

    pos_out += icnl_ndn_decode_name(out + pos_out, in, &pos_in, a);
    pos_out += icnl_ndn_decode_meta_info(out + pos_out, in, &pos_in, b);
    pos_out += icnl_ndn_decode_content(out + pos_out, in, &pos_in, a);
    pos_out += icnl_ndn_decode_signature_info(out + pos_out, in, &pos_in, a);
    pos_out += icnl_ndn_decode_signature_value(out + pos_out, in, &pos_in, in_len, a);

    memcpy(out + pos_out, in + pos_in, in_len - pos_in);
    pos_out += in_len - pos_in;

    uint8_t tmp[9];
    icnl_tlv_off_t tmp_len = 0;
    icnl_tlv_off_t ll = pos_out - (out_packet_length - out);
    icnl_ndn_tlv_write(ll - 1, tmp, &tmp_len);

    icnl_tlv_off_t skip = tmp_len - 1;

    if (skip) {
        memmove(out_packet_length + skip, out_packet_length, ll);
        pos_out += skip;
    }

    memcpy(out_packet_length, tmp, tmp_len);

    return pos_out;
}

icnl_tlv_off_t icnl_ndn_decode_data(uint8_t *out, const uint8_t *in, icnl_tlv_off_t in_len)
{
    memcpy(out, in, in_len);

    return in_len;
}

icnl_tlv_off_t icnl_ndn_decode(uint8_t *out, icnl_proto_t proto, const uint8_t *in,
                               icnl_tlv_off_t in_len)
{
    icnl_tlv_off_t pos = 0, out_len = 0;
    uint8_t *dispatch = (uint8_t *) (in + pos++);

    if (proto == ICNL_PROTO_NDN) {
        if (*dispatch == ICNL_DISPATCH_NDN_INT) {
            out_len = icnl_ndn_decode_interest(out, in + pos, in_len - pos);
        }
        else if (*dispatch == ICNL_DISPATCH_NDN_DATA) {
            out_len = icnl_ndn_decode_interest(out, in + pos, in_len - pos);
        }
    }
    else if (proto == ICNL_PROTO_NDN_HC) {
        if ((*dispatch & 0xF8) == ICNL_DISPATCH_NDN_INT_HC_A) {
            out_len = icnl_ndn_decode_interest_hc(out, in + pos, in_len - pos,
                                                  *dispatch);
        }
        else if ((*dispatch & 0xF8 ) == ICNL_DISPATCH_NDN_DATA_HC_A) {
            out_len = icnl_ndn_decode_data_hc(out, in + pos, in_len - pos,
                                              *dispatch);
        }
    }

    return out_len;
}
