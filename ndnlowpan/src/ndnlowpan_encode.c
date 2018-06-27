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

icnl_tlv_off_t icnl_ndn_encode_data(uint8_t *out, const uint8_t *in, icnl_tlv_off_t in_len)
{
    icnl_tlv_off_t pos = 0;

    out[pos++] = ICNL_DISPATCH_NDN_DATA;

    memcpy(out + pos, in, in_len);
    pos += in_len;

    return pos;
}

icnl_tlv_off_t icnl_ndn_encode_interest(uint8_t *out, const uint8_t *in, icnl_tlv_off_t in_len)
{
    icnl_tlv_off_t pos = 0;

    out[pos++] = ICNL_DISPATCH_NDN_INT;

    memcpy(out + pos, in, in_len);
    pos += in_len;

    return pos;
}

icnl_tlv_off_t icnl_ndn_encode_name(uint8_t *out, const uint8_t *in, icnl_tlv_off_t *pos_in, unsigned skip)
{
    icnl_tlv_off_t pos_out = 0, tmp_pos_out, name_len, len;

    name_len = icnl_ndn_tlv_read(in, pos_in);

    icnl_tlv_off_t end_pos = (*pos_in) + name_len;

    bool first = true;

    (*pos_in) += skip;

    if (*pos_in >= end_pos) {
        out[pos_out++] = 0x00;
        return pos_out;
    }

    do {
        /* skip component type */
        icnl_ndn_tlv_read(in, pos_in);
        len = icnl_ndn_tlv_read(in, pos_in);

        if (first) {
            tmp_pos_out = pos_out++;
            out[tmp_pos_out] = (len << 4) & 0xF0;
            first = false;
        }
        else {
            out[tmp_pos_out] |= (len << 0) & 0x0F;
            first = true;
        }

        memcpy(out + pos_out, in + *pos_in, len);
        pos_out += len;
        (*pos_in) += len;
    }
    while (*pos_in < end_pos);

    if (first) {
        out[pos_out++] = 0x00;
    }

    return pos_out;
}

icnl_tlv_off_t icnl_ndn_encode_nonce(uint8_t *out, const uint8_t *in, icnl_tlv_off_t *pos_in)
{
    icnl_tlv_off_t pos_out = 0;

    /* skip nonce length */
    icnl_ndn_tlv_read(in, pos_in);

    memcpy(out + pos_out, in + *pos_in, 4);
    pos_out += 4;
    *pos_in += 4;

    return pos_out;
}

icnl_tlv_off_t icnl_ndn_encode_selectors(uint8_t *out, const uint8_t *in, icnl_tlv_off_t *pos_in,
                                         uint8_t *b)
{
    (void) out;

    icnl_tlv_off_t pos_out = 0, res = 0;

    *b &= 0x01;

    icnl_tlv_off_t sel_len = icnl_ndn_tlv_read(in, pos_in) + *pos_in;

    while (*pos_in < sel_len) {
        icnl_tlv_off_t type = icnl_ndn_tlv_read(in, pos_in);

        switch (type) {
            case ICNL_NDN_TLV_MUST_BE_FRESH:
                res = 0;
                /* skip MustBeFresh TLV length */
                icnl_ndn_tlv_read(in, pos_in);
                *b |= 0x02;
                break;
            default:
                ICNL_DBG("error while encoding unknown Interest Selector TLV\n");
                return 0;
        }

        pos_out += res;
    }

    return pos_out;
}

icnl_tlv_off_t icnl_ndn_encode_meta_info(uint8_t *out, const uint8_t *in, icnl_tlv_off_t *pos_in,
                                         uint8_t *b)
{
    icnl_tlv_off_t pos_out = 0, res = 0, length;

    icnl_tlv_off_t meta_len = icnl_ndn_tlv_read(in, pos_in) + *pos_in;

    while (*pos_in < meta_len) {
        icnl_tlv_off_t type = icnl_ndn_tlv_read(in, pos_in);

        switch (type) {
            case ICNL_NDN_TLV_FRESHNESS_PERIOD:
                res = 0;
                length = icnl_ndn_tlv_read(in, pos_in);
                if (length == 1) {
                    *b |= 0x10;
                }
                else if (length == 2) {
                    *b |= 0x20;
                }
                else if (length == 4) {
                    *b |= 0x30;
                }
                else if (length == 8) {
                    *b |= 0x40;
                }

                memcpy(out + pos_out, in + *pos_in, length);
                *pos_in += length;
                pos_out += length;

                break;
            default:
                ICNL_DBG("error while encoding unknown Data MetaInfo TLV\n");
                return 0;
        }

        pos_out += res;
    }

    return pos_out;
}

icnl_tlv_off_t icnl_ndn_encode_content(uint8_t *out, const uint8_t *in, icnl_tlv_off_t *pos_in)
{
    icnl_tlv_off_t pos_out = 0;
    icnl_tlv_off_t length = icnl_ndn_tlv_read(in, pos_in);

    icnl_ndn_tlv_hc_write(length, out, &pos_out);

    memcpy(out + pos_out, in + *pos_in, length);
    pos_out += length;
    *pos_in += length;

    return pos_out;
}

icnl_tlv_off_t icnl_ndn_encode_signature_info(uint8_t *out, const uint8_t *in,
                                              icnl_tlv_off_t *pos_in)
{
    icnl_tlv_off_t pos_out = 0;
    icnl_tlv_off_t length = icnl_ndn_tlv_read(in, pos_in);

    icnl_ndn_tlv_hc_write(length, out, &pos_out);

    memcpy(out + pos_out, in + *pos_in, length);
    pos_out += length;
    *pos_in += length;

    return pos_out;
}

icnl_tlv_off_t icnl_ndn_encode_signature_value(uint8_t *out, const uint8_t *in,
                                               icnl_tlv_off_t *pos_in)
{
    icnl_tlv_off_t pos_out = 0;
    icnl_tlv_off_t length = icnl_ndn_tlv_read(in, pos_in);

    icnl_ndn_tlv_hc_write(length, out, &pos_out);

    memcpy(out + pos_out, in + *pos_in, length);
    pos_out += length;
    *pos_in += length;

    return pos_out;
}

icnl_tlv_off_t icnl_ndn_encode_interest_lifetime(uint8_t *out, const uint8_t *in,
                                                 icnl_tlv_off_t *pos_in)
{
    icnl_tlv_off_t pos_out = 0;
    const uint8_t *length;

    /* TODO: check for length == 2, only allow that */
    length = in + (*pos_in)++;

    memcpy(out + pos_out, in + *pos_in, *length);
    pos_out += *length;
    *pos_in += *length;

    return pos_out;
}

icnl_tlv_off_t icnl_ndn_encode_interest_hc(uint8_t *out, const uint8_t *in,
                                           icnl_tlv_off_t in_len,
                                           uint8_t *cids, unsigned cid_len,
                                           void *context)
{
    icnl_tlv_off_t pos_out = 0, pos_in = 0, res = 0;
    uint8_t *disp, *out_packet_length;
    unsigned skip_name_octets = 0;

    disp = out + (pos_out++);

    *disp = 0x80;

    if (cids) {
        *disp |= 0x01;
        uint8_t *cid_ptr, cid;
        for (unsigned i = 0; i < cid_len; i++) {
            cid_ptr = out + (pos_out++);
            cid = cids[i] & 0x7F;
            if (!(cid & 0x40) && icnl_cb_context_skip_prefix) {
                skip_name_octets = icnl_cb_context_skip_prefix(cid, context);
            }
            *cid_ptr = cid;
            if (i <  cid_len - 1) {
                *cid_ptr |= 0x80;
            }
        }
    }

    /* skip packet type */
    icnl_ndn_tlv_read(in, &pos_in);

    /* remember position of packet length */
    out_packet_length = out + (pos_out++);

    /* skip packet length */
    icnl_ndn_tlv_read(in, &pos_in);

    while (pos_in < in_len) {
        icnl_tlv_off_t type = icnl_ndn_tlv_read(in, &pos_in);

        switch (type) {
            case ICNL_NDN_TLV_NAME:
                res = icnl_ndn_encode_name(out + pos_out, in, &pos_in, skip_name_octets);
                break;
#if 0
            case ICNL_NDN_TLV_SELECTORS:
                res = icnl_ndn_encode_selectors(out + pos_out, in, &pos_in, &b);
                break;
#endif
            case ICNL_NDN_TLV_NONCE:
                res = icnl_ndn_encode_nonce(out + pos_out, in, &pos_in);
                break;
#if 0
            case ICNL_NDN_TLV_INTEREST_LIFETIME:
                res = icnl_ndn_encode_interest_lifetime(out + pos_out, in, &pos_in);
                break;
#endif
            default:
                ICNL_DBG("error while encoding unknown Interest TLV: 0x%02X\n", (unsigned int) type);
                return 0;
        }

        pos_out += res;
    }

    uint8_t tmp[9];
    icnl_tlv_off_t tmp_len = 0;
    icnl_tlv_off_t ll = pos_out - (out_packet_length - out);
    icnl_ndn_tlv_hc_write(ll - 1, tmp, &tmp_len);

    icnl_tlv_off_t skip = tmp_len - 1;

    if (skip) {
        memmove(out_packet_length + skip, out_packet_length, ll);
        pos_out += skip;
    }

    memcpy(out_packet_length, tmp, tmp_len);

    return pos_out;
}

icnl_tlv_off_t icnl_ndn_encode_data_hc(uint8_t *out, const uint8_t *in,
                                       icnl_tlv_off_t in_len,
                                       uint8_t *cids, unsigned cid_len,
                                       void *context)
{
    icnl_tlv_off_t pos_out = 0, pos_in = 0, res = 0;
    uint8_t *disp, *out_packet_length, hop_id = 0x00;
    unsigned skip_name_octets = 0;

    disp = out + (pos_out++);

    *disp = 0xC0;

    if (cids) {
        *disp |= 0x01;
        uint8_t *cid_ptr;

        hop_id = cids[0] & 0x7F;

        if ((hop_id & 0x40) && icnl_cb_hopid_skip_prefix) {
            skip_name_octets = icnl_cb_hopid_skip_prefix(hop_id, context);
        }

        for (unsigned i = 0; i < cid_len; i++) {
            cid_ptr = out + (pos_out++);
            *cid_ptr = cids[i] & 0x7F;
            if (i <  cid_len - 1) {
                *cid_ptr |= 0x80;
            }
        }
    }

    /* skip packet type */
    icnl_ndn_tlv_read(in, &pos_in);

    /* remember position of packet length */
    out_packet_length = out + (pos_out++);

    /* skip packet length */
    icnl_ndn_tlv_read(in, &pos_in);

    while (pos_in < in_len) {
        icnl_tlv_off_t type = icnl_ndn_tlv_read(in, &pos_in);

        switch (type) {
            case ICNL_NDN_TLV_NAME:
                res = icnl_ndn_encode_name(out + pos_out, in, &pos_in, skip_name_octets);
                break;
#if 0
            case ICNL_NDN_TLV_META_INFO:
                res = icnl_ndn_encode_meta_info(out + pos_out, in, &pos_in, &b);
                break;
#endif
            case ICNL_NDN_TLV_CONTENT:
                res = icnl_ndn_encode_content(out + pos_out, in, &pos_in);
                break;
            case ICNL_NDN_TLV_SIGNATURE_INFO:
                res = icnl_ndn_encode_signature_info(out + pos_out, in, &pos_in);
                break;
            case ICNL_NDN_TLV_SIGNATURE_VALUE:
                res = icnl_ndn_encode_signature_value(out + pos_out, in, &pos_in);
                break;
            default:
                ICNL_DBG("error while encoding unknown Data TLV\n");
                return 0;
        }

        pos_out += res;
    }

    uint8_t tmp[9];
    icnl_tlv_off_t tmp_len = 0;
    icnl_tlv_off_t ll = pos_out - (out_packet_length - out);
    icnl_ndn_tlv_hc_write(ll - 1, tmp, &tmp_len);

    icnl_tlv_off_t skip = tmp_len - 1;

    if (skip) {
        memmove(out_packet_length + skip, out_packet_length, ll);
        pos_out += skip;
    }

    memcpy(out_packet_length, tmp, tmp_len);

    return pos_out;
}

icnl_tlv_off_t icnl_ndn_encode(uint8_t *out, icnl_proto_t proto, const uint8_t *in,
                               icnl_tlv_off_t in_len, uint8_t *cids, unsigned cid_len,
                               void *context)
{
    icnl_tlv_off_t pos = 0;

    if (proto == ICNL_PROTO_NDN) {
        if (in[0] == 0x05) {
            pos += icnl_ndn_encode_interest(out, in, in_len);
        }
        else if (in[0] == 0x06) {
            pos += icnl_ndn_encode_data(out, in, in_len);
        }
    }
    else if (proto == ICNL_PROTO_NDN_HC) {
        if (in[0] == 0x05) {
            pos += icnl_ndn_encode_interest_hc(out, in, in_len, cids, cid_len, context);
        }
        else if (in[0] == 0x06) {
            pos += icnl_ndn_encode_data_hc(out, in, in_len, cids, cid_len, context);
        }
    }

    return pos;
}
