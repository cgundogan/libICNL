/*
 * Copyright (C) 2018 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdbool.h>
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
                                    icnl_tlv_off_t *pos_in, uint8_t hop_id,
                                    uint8_t *prefix_cid,
                                    void *context)
{
    icnl_tlv_off_t pos_out = 0;
    uint8_t out_total_name_len = 0;
    uint8_t *name_length;

    out[pos_out++] = ICNL_NDN_TLV_NAME;

    name_length = out + (pos_out++);
    /* skip maximum amount of possible length field size */
    pos_out += 8;

    uint8_t tmp_len, tmp_len_masked;
    bool first = true;

    if (prefix_cid && icnl_cb_context_decompress_name) {
        pos_out += out_total_name_len = icnl_cb_context_decompress_name((out + pos_out), (*prefix_cid) & 0x7F, context);
    }

    if ((hop_id & 0x40) && icnl_cb_hopid_decompress_name) {
        pos_out += out_total_name_len = icnl_cb_hopid_decompress_name((out + pos_out), hop_id & 0x7F, context);
    }

    while (true) {

        if (first) {
            tmp_len = in[(*pos_in)++];
            tmp_len_masked = (tmp_len & 0xF0) >> 4;
            first = false;
        }
        else {
            tmp_len_masked = (tmp_len & 0x0F) >> 0;
            first = true;
        }

        if (tmp_len_masked == 0) {
            break;
        }

        /* write type */
        out[pos_out++] = ICNL_NDN_TLV_GENERIC_NAME_COMPONENT;
        out_total_name_len += 1;

        /* write length */
        icnl_ndn_tlv_write(tmp_len_masked, out, &pos_out);
        out_total_name_len += 1;

        memcpy(out + pos_out, in + *pos_in, tmp_len_masked);
        pos_out += tmp_len_masked;
        *pos_in += tmp_len_masked;
        out_total_name_len += tmp_len_masked;
    }

    icnl_tlv_off_t tmp = 0;
    icnl_ndn_tlv_write(out_total_name_len, name_length, &tmp);
    memmove(name_length + tmp, name_length + 9, pos_out);
    pos_out -= 9 - tmp;

    return pos_out;
}

icnl_tlv_off_t icnl_ndn_decode_nonce(uint8_t *out, const uint8_t *in,
                                     icnl_tlv_off_t *pos_in)
{
    icnl_tlv_off_t pos_out = 0;

    out[pos_out++] = ICNL_NDN_TLV_NONCE;
    out[pos_out++] = 4;

    memcpy(out + pos_out, in + *pos_in, 4);
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
                                       icnl_tlv_off_t *pos_in)
{
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
                                              icnl_tlv_off_t *pos_in)
{
    icnl_tlv_off_t pos_out = 0, len;

    len = icnl_ndn_tlv_hc_read(in, pos_in);

    out[pos_out++] = ICNL_NDN_TLV_SIGNATURE_INFO;
    icnl_ndn_tlv_write(len, out, &pos_out);

    memcpy(out + pos_out, in + *pos_in, len);
    *pos_in += len;
    pos_out += len;

    return pos_out;
}

icnl_tlv_off_t icnl_ndn_decode_signature_value(uint8_t *out, const uint8_t *in,
                                               icnl_tlv_off_t *pos_in)
{
    icnl_tlv_off_t pos_out = 0, len;

    len = icnl_ndn_tlv_hc_read(in, pos_in);

    out[pos_out++] = ICNL_NDN_TLV_SIGNATURE_VALUE;
    icnl_ndn_tlv_write(len, out, &pos_out);

    memcpy(out + pos_out, in + *pos_in, len);
    *pos_in += len;
    pos_out += len;

    return pos_out;
}

icnl_tlv_off_t icnl_ndn_decode_interest_hc(uint8_t *out, const uint8_t *in,
                                           icnl_tlv_off_t in_len, uint8_t dispatch,
                                           void *context)
{
    icnl_tlv_off_t pos_out = 0, pos_in = 0;
    uint8_t *out_packet_length, *prefix_cid = NULL;

    if (dispatch & 0x01) {
        bool first = true;
        uint8_t cid = in[pos_in];

        if ((cid & 0x40) && icnl_cb_hopid) {
            icnl_cb_hopid(cid & 0x7F);
            first = false;
        }

        if (first || (cid & 0x80)) {
            if (!first) {
                pos_in++;
            }
            if (!prefix_cid) {
                prefix_cid = (uint8_t *) (in + pos_in);
                cid = in[pos_in++];
            }

            while (cid & 0x80) {
                cid = in[pos_in++];
                /* do nothing for now */
            }
        }
    }

    out[pos_out++] = ICNL_NDN_TLV_INTEREST;
    out_packet_length = out + (pos_out++);

    /* skip packet length */
    icnl_ndn_tlv_hc_read(in, &pos_in);

    pos_out += icnl_ndn_decode_name(out + pos_out, in, &pos_in, 0, prefix_cid, context);
#if 0
    pos_out += icnl_ndn_decode_selectors(out + pos_out, in, &pos_in, b);
#endif
    pos_out += icnl_ndn_decode_nonce(out + pos_out, in, &pos_in);
#if 0
    pos_out += icnl_ndn_decode_interest_lifetime(out + pos_out, in, &pos_in, a);
#endif

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
                                       icnl_tlv_off_t in_len, uint8_t dispatch,
                                       void *context)
{
    (void) dispatch;
    icnl_tlv_off_t pos_out = 0, pos_in = 0;
    uint8_t *out_packet_length, hop_id = 0;

    if (dispatch & 0x01) {
        uint8_t cid = hop_id = in[pos_in++];

        while (cid & 0x80) {
            cid = in[pos_in++];
            /* do nothin for now */
        }
    }

    out[pos_out++] = ICNL_NDN_TLV_DATA;
    out_packet_length = out + (pos_out++);

    /* skip packet length */
    icnl_ndn_tlv_hc_read(in, &pos_in);

    pos_out += icnl_ndn_decode_name(out + pos_out, in, &pos_in, hop_id, NULL, context);
#if 0
    pos_out += icnl_ndn_decode_meta_info(out + pos_out, in, &pos_in, b);
#endif
    pos_out += icnl_ndn_decode_content(out + pos_out, in, &pos_in);
    pos_out += icnl_ndn_decode_signature_info(out + pos_out, in, &pos_in);
    pos_out += icnl_ndn_decode_signature_value(out + pos_out, in, &pos_in);

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
                               icnl_tlv_off_t in_len, void *context)
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
        if (((*dispatch) & 0x40) == 0) {
            out_len = icnl_ndn_decode_interest_hc(out, in + pos, in_len - pos,
                                                  *dispatch, context);
        }
        else {
            out_len = icnl_ndn_decode_data_hc(out, in + pos, in_len - pos,
                                              *dispatch, context);
        }
    }

    return out_len;
}
