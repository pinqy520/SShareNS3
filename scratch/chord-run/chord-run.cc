/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

// Network topology
//
//       n0    n1   n2   n3                     nx
//       |     |    |    |  . . . . . . . . . . |
//       ========================================
//                          LAN
//

#include <fstream>
#include <stdlib.h>
#include <stdint.h>
#include <iostream>
#include <string.h>
#include <vector>
//#include <openssl/sha.h>
#include "ns3/core-module.h"
//#include "ns3/common-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
//#include "ns3/helper-module.h"
#include "ns3/csma-module.h"
#include "ns3/chord-ipv4-helper.h"
#include "ns3/chord-ipv4.h"
#include "ns3/object.h"
#include "ns3/nstime.h"


#include <stdio.h>
//#include <stdint.h>
//#include <string.h>
#include <assert.h>

//字节序的小头和大头的问题
#define ZEN_LITTLE_ENDIAN  0x0123
#define ZEN_BIG_ENDIAN     0x3210

//目前所有的代码都是为了小头党服务的，不知道有生之年这套代码是否还会为大头党服务一次？
#ifndef ZEN_BYTES_ORDER
#define ZEN_BYTES_ORDER    ZEN_LITTLE_ENDIAN
#endif

#ifndef ZEN_SWAP_UINT16
#define ZEN_SWAP_UINT16(x)  ((((x) & 0xff00) >>  8) | (((x) & 0x00ff) <<  8))
#endif
#ifndef ZEN_SWAP_UINT32
#define ZEN_SWAP_UINT32(x)  ((((x) & 0xff000000) >> 24) | (((x) & 0x00ff0000) >>  8) | \
    (((x) & 0x0000ff00) <<  8) | (((x) & 0x000000ff) << 24))
#endif
#ifndef ZEN_SWAP_UINT64
#define ZEN_SWAP_UINT64(x)  ((((x) & 0xff00000000000000) >> 56) | (((x) & 0x00ff000000000000) >>  40) | \
    (((x) & 0x0000ff0000000000) >> 24) | (((x) & 0x000000ff00000000) >>  8) | \
    (((x) & 0x00000000ff000000) << 8 ) | (((x) & 0x0000000000ff0000) <<  24) | \
    (((x) & 0x000000000000ff00) << 40 ) | (((x) & 0x00000000000000ff) <<  56))
#endif

//将一个（字符串）数组，拷贝到另外一个uint32_t数组，同时每个uint32_t反字节序
void *swap_uint32_memcpy(void *to, const void *from, size_t length)
{
    memcpy(to, from, length);
    size_t remain_len =  (4 - (length & 3)) & 3;

    //数据不是4字节的倍数,补充0
    if (remain_len)
    {
        for (size_t i = 0; i < remain_len; ++i)
        {
            *((char *)(to) + length + i) = 0;
        }
        //调整成4的倍数
        length += remain_len;
    }

    //所有的数据反转
    for (size_t i = 0; i < length / 4; ++i)
    {
        ((uint32_t *)to)[i] = ZEN_SWAP_UINT32(((uint32_t *)to)[i]);
    }

    return to;
}

///MD5的结果数据长度
static const size_t ZEN_MD5_HASH_SIZE   = 16;
///SHA1的结果数据长度
static const size_t ZEN_SHA1_HASH_SIZE  = 20;



namespace ZEN_LIB
{


/*!
@brief      求某个内存块的MD5，
@return     unsigned char* 返回的的结果，
@param[in]  buf    求MD5的内存BUFFER指针
@param[in]  size   BUFFER长度
@param[out] result 结果
*/
unsigned char *md5(const unsigned char *buf,
                   size_t size,
                   unsigned char result[ZEN_MD5_HASH_SIZE]);


/*!
@brief      求内存块BUFFER的SHA1值
@return     unsigned char* 返回的的结果
@param[in]  buf    求SHA1的内存BUFFER指针
@param[in]  size   BUFFER长度
@param[out] result 结果
*/
unsigned char *sha1(const unsigned char *buf,
                    size_t size,
                    unsigned char result[ZEN_SHA1_HASH_SIZE]);
};


//================================================================================================
//MD5算法

//每次处理的BLOCK的大小
static const size_t ZEN_MD5_BLOCK_SIZE = 64;

//md5算法的上下文，保存一些状态，中间数据，结果
typedef struct md5_ctx
{
    //处理的数据的长度
    uint64_t length_;
    //还没有处理的数据长度
    uint64_t unprocessed_;
    //取得的HASH结果（中间数据）
    uint32_t  hash_[4];
} md5_ctx;

#define ROTL32(dword, n) ((dword) << (n) ^ ((dword) >> (32 - (n))))
#define ROTR32(dword, n) ((dword) >> (n) ^ ((dword) << (32 - (n))))
#define ROTL64(qword, n) ((qword) << (n) ^ ((qword) >> (64 - (n))))
#define ROTR64(qword, n) ((qword) >> (n) ^ ((qword) << (64 - (n))))

/*!
@brief      内部函数，初始化MD5的context，内容
@param      ctx
*/
static void zen_md5_init(md5_ctx *ctx)
{
    ctx->length_ = 0;
    ctx->unprocessed_ = 0;

    /* initialize state */
    ctx->hash_[0] = 0x67452301;
    ctx->hash_[1] = 0xefcdab89;
    ctx->hash_[2] = 0x98badcfe;
    ctx->hash_[3] = 0x10325476;
}

/* First, define four auxiliary functions that each take as input
 * three 32-bit words and returns a 32-bit word.*/

/* F(x,y,z) = ((y XOR z) AND x) XOR z - is faster then original version */
#define MD5_F(x, y, z) ((((y) ^ (z)) & (x)) ^ (z))
#define MD5_G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define MD5_H(x, y, z) ((x) ^ (y) ^ (z))
#define MD5_I(x, y, z) ((y) ^ ((x) | (~z)))

/* transformations for rounds 1, 2, 3, and 4. */
#define MD5_ROUND1(a, b, c, d, x, s, ac) { \
        (a) += MD5_F((b), (c), (d)) + (x) + (ac); \
        (a) = ROTL32((a), (s)); \
        (a) += (b); \
    }
#define MD5_ROUND2(a, b, c, d, x, s, ac) { \
        (a) += MD5_G((b), (c), (d)) + (x) + (ac); \
        (a) = ROTL32((a), (s)); \
        (a) += (b); \
    }
#define MD5_ROUND3(a, b, c, d, x, s, ac) { \
        (a) += MD5_H((b), (c), (d)) + (x) + (ac); \
        (a) = ROTL32((a), (s)); \
        (a) += (b); \
    }
#define MD5_ROUND4(a, b, c, d, x, s, ac) { \
        (a) += MD5_I((b), (c), (d)) + (x) + (ac); \
        (a) = ROTL32((a), (s)); \
        (a) += (b); \
    }


/*!
@brief      内部函数，将64个字节，16个uint32_t的数组进行摘要（杂凑）处理，处理的数据自己序是小头数据
@param      state 存放处理的hash数据结果
@param      block 要处理的block，64个字节，16个uint32_t的数组
*/
static void zen_md5_process_block(uint32_t state[4], const uint32_t block[ZEN_MD5_BLOCK_SIZE / 4])
{
    register unsigned a, b, c, d;
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];

    const uint32_t *x = NULL;

    //MD5里面计算的数据都是小头数据.大头党的数据要处理
#if ZEN_BYTES_ORDER == ZEN_LITTLE_ENDIAN
    x = block;
#else
    uint32_t swap_block[ZEN_MD5_BLOCK_SIZE / 4];
    swap_uint32_memcpy(swap_block, block, 64);
    x = swap_block;
#endif


    MD5_ROUND1(a, b, c, d, x[ 0],  7, 0xd76aa478);
    MD5_ROUND1(d, a, b, c, x[ 1], 12, 0xe8c7b756);
    MD5_ROUND1(c, d, a, b, x[ 2], 17, 0x242070db);
    MD5_ROUND1(b, c, d, a, x[ 3], 22, 0xc1bdceee);
    MD5_ROUND1(a, b, c, d, x[ 4],  7, 0xf57c0faf);
    MD5_ROUND1(d, a, b, c, x[ 5], 12, 0x4787c62a);
    MD5_ROUND1(c, d, a, b, x[ 6], 17, 0xa8304613);
    MD5_ROUND1(b, c, d, a, x[ 7], 22, 0xfd469501);
    MD5_ROUND1(a, b, c, d, x[ 8],  7, 0x698098d8);
    MD5_ROUND1(d, a, b, c, x[ 9], 12, 0x8b44f7af);
    MD5_ROUND1(c, d, a, b, x[10], 17, 0xffff5bb1);
    MD5_ROUND1(b, c, d, a, x[11], 22, 0x895cd7be);
    MD5_ROUND1(a, b, c, d, x[12],  7, 0x6b901122);
    MD5_ROUND1(d, a, b, c, x[13], 12, 0xfd987193);
    MD5_ROUND1(c, d, a, b, x[14], 17, 0xa679438e);
    MD5_ROUND1(b, c, d, a, x[15], 22, 0x49b40821);

    MD5_ROUND2(a, b, c, d, x[ 1],  5, 0xf61e2562);
    MD5_ROUND2(d, a, b, c, x[ 6],  9, 0xc040b340);
    MD5_ROUND2(c, d, a, b, x[11], 14, 0x265e5a51);
    MD5_ROUND2(b, c, d, a, x[ 0], 20, 0xe9b6c7aa);
    MD5_ROUND2(a, b, c, d, x[ 5],  5, 0xd62f105d);
    MD5_ROUND2(d, a, b, c, x[10],  9,  0x2441453);
    MD5_ROUND2(c, d, a, b, x[15], 14, 0xd8a1e681);
    MD5_ROUND2(b, c, d, a, x[ 4], 20, 0xe7d3fbc8);
    MD5_ROUND2(a, b, c, d, x[ 9],  5, 0x21e1cde6);
    MD5_ROUND2(d, a, b, c, x[14],  9, 0xc33707d6);
    MD5_ROUND2(c, d, a, b, x[ 3], 14, 0xf4d50d87);
    MD5_ROUND2(b, c, d, a, x[ 8], 20, 0x455a14ed);
    MD5_ROUND2(a, b, c, d, x[13],  5, 0xa9e3e905);
    MD5_ROUND2(d, a, b, c, x[ 2],  9, 0xfcefa3f8);
    MD5_ROUND2(c, d, a, b, x[ 7], 14, 0x676f02d9);
    MD5_ROUND2(b, c, d, a, x[12], 20, 0x8d2a4c8a);

    MD5_ROUND3(a, b, c, d, x[ 5],  4, 0xfffa3942);
    MD5_ROUND3(d, a, b, c, x[ 8], 11, 0x8771f681);
    MD5_ROUND3(c, d, a, b, x[11], 16, 0x6d9d6122);
    MD5_ROUND3(b, c, d, a, x[14], 23, 0xfde5380c);
    MD5_ROUND3(a, b, c, d, x[ 1],  4, 0xa4beea44);
    MD5_ROUND3(d, a, b, c, x[ 4], 11, 0x4bdecfa9);
    MD5_ROUND3(c, d, a, b, x[ 7], 16, 0xf6bb4b60);
    MD5_ROUND3(b, c, d, a, x[10], 23, 0xbebfbc70);
    MD5_ROUND3(a, b, c, d, x[13],  4, 0x289b7ec6);
    MD5_ROUND3(d, a, b, c, x[ 0], 11, 0xeaa127fa);
    MD5_ROUND3(c, d, a, b, x[ 3], 16, 0xd4ef3085);
    MD5_ROUND3(b, c, d, a, x[ 6], 23,  0x4881d05);
    MD5_ROUND3(a, b, c, d, x[ 9],  4, 0xd9d4d039);
    MD5_ROUND3(d, a, b, c, x[12], 11, 0xe6db99e5);
    MD5_ROUND3(c, d, a, b, x[15], 16, 0x1fa27cf8);
    MD5_ROUND3(b, c, d, a, x[ 2], 23, 0xc4ac5665);

    MD5_ROUND4(a, b, c, d, x[ 0],  6, 0xf4292244);
    MD5_ROUND4(d, a, b, c, x[ 7], 10, 0x432aff97);
    MD5_ROUND4(c, d, a, b, x[14], 15, 0xab9423a7);
    MD5_ROUND4(b, c, d, a, x[ 5], 21, 0xfc93a039);
    MD5_ROUND4(a, b, c, d, x[12],  6, 0x655b59c3);
    MD5_ROUND4(d, a, b, c, x[ 3], 10, 0x8f0ccc92);
    MD5_ROUND4(c, d, a, b, x[10], 15, 0xffeff47d);
    MD5_ROUND4(b, c, d, a, x[ 1], 21, 0x85845dd1);
    MD5_ROUND4(a, b, c, d, x[ 8],  6, 0x6fa87e4f);
    MD5_ROUND4(d, a, b, c, x[15], 10, 0xfe2ce6e0);
    MD5_ROUND4(c, d, a, b, x[ 6], 15, 0xa3014314);
    MD5_ROUND4(b, c, d, a, x[13], 21, 0x4e0811a1);
    MD5_ROUND4(a, b, c, d, x[ 4],  6, 0xf7537e82);
    MD5_ROUND4(d, a, b, c, x[11], 10, 0xbd3af235);
    MD5_ROUND4(c, d, a, b, x[ 2], 15, 0x2ad7d2bb);
    MD5_ROUND4(b, c, d, a, x[ 9], 21, 0xeb86d391);

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}


/*!
@brief      内部函数，处理数据的前面部分(>64字节的部分)，每次组成一个64字节的block就进行杂凑处理
@param[out] ctx  算法的context，用于记录一些处理的上下文和结果
@param[in]  buf  处理的数据，
@param[in]  size 处理的数据长度
*/
static void zen_md5_update(md5_ctx *ctx, const unsigned char *buf, size_t size)
{
    //为什么不是=，因为在某些环境下，可以多次调用zen_md5_update，但这种情况，必须保证前面的调用，每次都没有unprocessed_
    ctx->length_ += size;

    //每个处理的块都是64字节
    while (size >= ZEN_MD5_BLOCK_SIZE)
    {
        zen_md5_process_block(ctx->hash_, reinterpret_cast<const uint32_t *>(buf));
        buf  += ZEN_MD5_BLOCK_SIZE;
        size -= ZEN_MD5_BLOCK_SIZE;
    }

    ctx->unprocessed_ = size;
}


/*!
@brief      内部函数，处理数据的末尾部分，我们要拼出最后1个（或者两个）要处理的BLOCK，加上0x80，加上长度进行处理
@param[in]  ctx    算法的context，用于记录一些处理的上下文和结果
@param[in]  buf    处理的数据
@param[in]  size   处理buffer的长度
@param[out] result 返回的结果，
*/
static void zen_md5_final(md5_ctx *ctx, const unsigned char *buf, size_t size, unsigned char *result)
{
    uint32_t message[ZEN_MD5_BLOCK_SIZE / 4];

    //保存剩余的数据，我们要拼出最后1个（或者两个）要处理的块，前面的算法保证了，最后一个块肯定小于64个字节
    if (ctx->unprocessed_)
    {
        memcpy(message, buf + size - ctx->unprocessed_, static_cast<size_t>( ctx->unprocessed_));
    }

    //得到0x80要添加在的位置（在uint32_t 数组中），
    uint32_t index = ((uint32_t)ctx->length_ & 63) >> 2;
    uint32_t shift = ((uint32_t)ctx->length_ & 3) * 8;

    //添加0x80进去，并且把余下的空间补充0
    message[index]   &= ~(0xFFFFFFFF << shift);
    message[index++] ^= 0x80 << shift;

    //如果这个block还无法处理，其后面的长度无法容纳长度64bit，那么先处理这个block
    if (index > 14)
    {
        while (index < 16)
        {
            message[index++] = 0;
        }

        zen_md5_process_block(ctx->hash_, message);
        index = 0;
    }

    //补0
    while (index < 14)
    {
        message[index++] = 0;
    }

    //保存长度，注意是bit位的长度,这个问题让我看着郁闷了半天，
    uint64_t data_len = (ctx->length_) << 3;

    //注意MD5算法要求的64bit的长度是小头LITTLE-ENDIAN编码，注意下面的比较是!=
#if ZEN_BYTES_ORDER != ZEN_LITTLE_ENDIAN
    data_len = ZEN_SWAP_UINT64(data_len);
#endif

    message[14] = (uint32_t) (data_len & 0x00000000FFFFFFFF);
    message[15] = (uint32_t) ((data_len & 0xFFFFFFFF00000000ULL) >> 32);

    zen_md5_process_block(ctx->hash_, message);

    //注意结果是小头党的，在大头的世界要进行转换
#if ZEN_BYTES_ORDER == ZEN_LITTLE_ENDIAN
    memcpy(result, &ctx->hash_, ZEN_MD5_HASH_SIZE);
#else
    swap_uint32_memcpy(result, &ctx->hash_, ZEN_MD5_HASH_SIZE);
#endif

}


//计算一个内存数据的MD5值
unsigned char *ZEN_LIB::md5(const unsigned char *buf,
                            size_t size,
                            unsigned char result[ZEN_MD5_HASH_SIZE])
{
    assert(result != NULL);

    md5_ctx ctx;
    zen_md5_init(&ctx);
    zen_md5_update(&ctx, buf, size);
    zen_md5_final(&ctx, buf, size, result);
    return result;
}




//================================================================================================
//SHA1的算法

//每次处理的BLOCK的大小
static const size_t ZEN_SHA1_BLOCK_SIZE = 64;

//SHA1算法的上下文，保存一些状态，中间数据，结果
typedef struct sha1_ctx
{

    //处理的数据的长度
    uint64_t length_;
    //还没有处理的数据长度
    uint64_t unprocessed_;
    /* 160-bit algorithm internal hashing state */
    uint32_t hash_[5];
} sha1_ctx;

//内部函数，SHA1算法的上下文的初始化
static void zen_sha1_init(sha1_ctx *ctx)
{
    ctx->length_ = 0;
    ctx->unprocessed_ = 0;
    // 初始化算法的几个常量，魔术数
    ctx->hash_[0] = 0x67452301;
    ctx->hash_[1] = 0xefcdab89;
    ctx->hash_[2] = 0x98badcfe;
    ctx->hash_[3] = 0x10325476;
    ctx->hash_[4] = 0xc3d2e1f0;
}


/*!
@brief      内部函数，对一个64bit内存块进行摘要(杂凑)处理，
@param      hash  存放计算hash结果的的数组
@param      block 要计算的处理得内存块
*/
static void zen_sha1_process_block(uint32_t hash[5],
                                   const uint32_t block[ZEN_SHA1_BLOCK_SIZE / 4])
{
    size_t        t;
    uint32_t      wblock[80];
    register uint32_t      a, b, c, d, e, temp;

    //SHA1算法处理的内部数据要求是大头党的，在小头的环境转换
#if ZEN_BYTES_ORDER == ZEN_LITTLE_ENDIAN
    swap_uint32_memcpy(wblock, block, ZEN_SHA1_BLOCK_SIZE);
#else
    ::memcpy(wblock, block, ZEN_SHA1_BLOCK_SIZE);
#endif

    //处理
    for (t = 16; t < 80; t++)
    {
        wblock[t] = ROTL32(wblock[t - 3] ^ wblock[t - 8] ^ wblock[t - 14] ^ wblock[t - 16], 1);
    }

    a = hash[0];
    b = hash[1];
    c = hash[2];
    d = hash[3];
    e = hash[4];

    for (t = 0; t < 20; t++)
    {
        /* the following is faster than ((B & C) | ((~B) & D)) */
        temp =  ROTL32(a, 5) + (((c ^ d) & b) ^ d)
                + e + wblock[t] + 0x5A827999;
        e = d;
        d = c;
        c = ROTL32(b, 30);
        b = a;
        a = temp;
    }

    for (t = 20; t < 40; t++)
    {
        temp = ROTL32(a, 5) + (b ^ c ^ d) + e + wblock[t] + 0x6ED9EBA1;
        e = d;
        d = c;
        c = ROTL32(b, 30);
        b = a;
        a = temp;
    }

    for (t = 40; t < 60; t++)
    {
        temp = ROTL32(a, 5) + ((b & c) | (b & d) | (c & d))
               + e + wblock[t] + 0x8F1BBCDC;
        e = d;
        d = c;
        c = ROTL32(b, 30);
        b = a;
        a = temp;
    }

    for (t = 60; t < 80; t++)
    {
        temp = ROTL32(a, 5) + (b ^ c ^ d) + e + wblock[t] + 0xCA62C1D6;
        e = d;
        d = c;
        c = ROTL32(b, 30);
        b = a;
        a = temp;
    }

    hash[0] += a;
    hash[1] += b;
    hash[2] += c;
    hash[3] += d;
    hash[4] += e;
}


/*!
@brief      内部函数，处理数据的前面部分(>64字节的部分)，每次组成一个64字节的block就进行杂凑处理
@param      ctx  算法的上下文，记录中间数据，结果等
@param      msg  要进行计算的数据buffer
@param      size 长度
*/
static void zen_sha1_update(sha1_ctx *ctx,
                            const unsigned char *buf, 
                            size_t size)
{
    //为了让zen_sha1_update可以多次进入，长度可以累计
    ctx->length_ += size;

    //每个处理的块都是64字节
    while (size >= ZEN_SHA1_BLOCK_SIZE)
    {
        zen_sha1_process_block(ctx->hash_, reinterpret_cast<const uint32_t *>(buf));
        buf  += ZEN_SHA1_BLOCK_SIZE;
        size -= ZEN_SHA1_BLOCK_SIZE;
    }

    ctx->unprocessed_ = size;
}


/*!
@brief      内部函数，处理数据的最后部分，添加0x80,补0，增加长度信息
@param      ctx    算法的上下文，记录中间数据，结果等
@param      msg    要进行计算的数据buffer
@param      result 返回的结果
*/
static void zen_sha1_final(sha1_ctx *ctx, 
                           const unsigned char *msg,
                           size_t size, 
                           unsigned char *result)
{

    uint32_t message[ZEN_SHA1_BLOCK_SIZE / 4];

    //保存剩余的数据，我们要拼出最后1个（或者两个）要处理的块，前面的算法保证了，最后一个块肯定小于64个字节
    if (ctx->unprocessed_)
    {
        memcpy(message, msg + size - ctx->unprocessed_, static_cast<size_t>( ctx->unprocessed_));
    }

    //得到0x80要添加在的位置（在uint32_t 数组中），
    uint32_t index = ((uint32_t)ctx->length_ & 63) >> 2;
    uint32_t shift = ((uint32_t)ctx->length_ & 3) * 8;

    //添加0x80进去，并且把余下的空间补充0
    message[index]   &= ~(0xFFFFFFFF << shift);
    message[index++] ^= 0x80 << shift;

    //如果这个block还无法处理，其后面的长度无法容纳长度64bit，那么先处理这个block
    if (index > 14)
    {
        while (index < 16)
        {
            message[index++] = 0;
        }

        zen_sha1_process_block(ctx->hash_, message);
        index = 0;
    }

    //补0
    while (index < 14)
    {
        message[index++] = 0;
    }

    //保存长度，注意是bit位的长度,这个问题让我看着郁闷了半天，
    uint64_t data_len = (ctx->length_) << 3;

    //注意SHA1算法要求的64bit的长度是大头BIG-ENDIAN，在小头的世界要进行转换
#if ZEN_BYTES_ORDER == ZEN_LITTLE_ENDIAN
    data_len = ZEN_SWAP_UINT64(data_len);
#endif

    message[14] = (uint32_t) (data_len & 0x00000000FFFFFFFF);
    message[15] = (uint32_t) ((data_len & 0xFFFFFFFF00000000ULL) >> 32);

    zen_sha1_process_block(ctx->hash_, message);

    //注意结果是大头党的，在小头的世界要进行转换
#if ZEN_BYTES_ORDER == ZEN_LITTLE_ENDIAN
    swap_uint32_memcpy(result, &ctx->hash_, ZEN_SHA1_HASH_SIZE);
#else
    memcpy(result, &ctx->hash_, ZEN_SHA1_HASH_SIZE);
#endif
}



//计算一个内存数据的SHA1值
unsigned char *ZEN_LIB::sha1(const unsigned char *msg,
                             size_t size,
                             unsigned char result[ZEN_SHA1_HASH_SIZE])
{
    assert(result != NULL);

    sha1_ctx ctx;
    zen_sha1_init(&ctx);
    zen_sha1_update(&ctx, msg, size);
    zen_sha1_final(&ctx, msg, size, result);
    return result;
}


using namespace ns3;

NS_LOG_COMPONENT_DEFINE("ChordRun");

struct CommandHandlerArgument
{
  std::string scriptFile;
  NodeContainer nodeContainer;
  void *chordRun;
};

class ChordRun
{

 public:

    void Start (std::string scriptFile, NodeContainer nodeContainer);
    void Stop ();

    //Chord
    void InsertVNode(Ptr<ChordIpv4> chordApplication, std::string vNodeName);
    void Lookup (Ptr<ChordIpv4> chordApplication, std::string resourceName);

    //DHash
    void Insert (Ptr<ChordIpv4> chordApplication, std::string resourceName, std::string resourceValue);
    void Retrieve (Ptr<ChordIpv4> chordApplication, std::string resourceName);

    //Crash Testing
    void DetachNode(uint16_t nodeNumber);
    void ReAttachNode(uint16_t nodeNumber);
    void CrashChord(Ptr<ChordIpv4> chordApplication);
    void RestartChord(Ptr<ChordIpv4> chordApplication);

    // Call backs by Chord Layer
    void JoinSuccess (std::string vNodeName, uint8_t* key, uint8_t numBytes);
    void LookupSuccess (uint8_t* lookupKey, uint8_t lookupKeyBytes, Ipv4Address ipAddress, uint16_t port);
    void LookupFailure (uint8_t* lookupKey, uint8_t lookupKeyBytes);
    void InsertSuccess (uint8_t* key, uint8_t numBytes, uint8_t* object, uint32_t objectBytes);
    void RetrieveSuccess (uint8_t* key, uint8_t numBytes, uint8_t* object, uint32_t objectBytes);
    void InsertFailure (uint8_t* key, uint8_t numBytes, uint8_t* object, uint32_t objectBytes);
    void RetrieveFailure (uint8_t* key, uint8_t numBytes);
    void VNodeKeyOwnership (std::string vNodeName, uint8_t* key, uint8_t keyBytes, uint8_t* predecessorKey, uint8_t predecessorKeyBytes
			   ,uint8_t* oldPredecessorKey, uint8_t oldPredecessorKeyBytes, Ipv4Address predecessorIp, uint16_t predecessorPort);


    //Statistics
    void TraceRing (std::string vNodeName, uint8_t* key, uint8_t numBytes);
    void VNodeFailure (std::string vNodeName, uint8_t* key, uint8_t numBytes);
    void DumpVNodeInfo ( Ptr<ChordIpv4> chordApplication, std::string vNodeName);
    void DumpDHashInfo (Ptr<ChordIpv4> chordApplication);

    //Keyboard Handlers
    static void *CommandHandler (void *arg);
    void Tokenize(const std::string& str, std::vector<std::string>& tokens, const std::string& delimiters);
    void ProcessCommandTokens (std::vector<std::string> tokens, Time time);
    void ReadCommandTokens (void);


    pthread_t commandHandlerThreadId;
    struct CommandHandlerArgument th_argument;

  private:
    ChordRun* m_chordRun;
    std::string m_scriptFile;
    NodeContainer m_nodeContainer;
    std::vector<std::string> m_tokens;
    bool m_readyToRead;
    
    //Print
    void PrintCharArray (uint8_t*, uint32_t, std::ostream&);
    void PrintHexArray (uint8_t*, uint32_t, std::ostream&);

};

 void
 ChordRun::Start (std::string scriptFile, NodeContainer nodeContainer)
 {

  NS_LOG_FUNCTION_NOARGS();
  th_argument.scriptFile = scriptFile;
  th_argument.nodeContainer  = nodeContainer;
  th_argument.chordRun = (void *)this;
  this->m_chordRun = this;
  this->m_nodeContainer = nodeContainer;

  m_readyToRead = false;
  //process script-file
  if (scriptFile != "")                                 //Start reading the script file.....if not null
  {
    std::ifstream file;
    file.open (scriptFile.c_str());
    if (file.is_open())
    {
      NS_LOG_INFO ("Reading Script File: " << scriptFile);
      Time time = MilliSeconds (0.0);
      std::string commandLine;
      while (!file.eof())
      {
        std::getline (file, commandLine, '\n');
        std::cout << "Adding Command: " << commandLine << std::endl;
        m_chordRun->Tokenize (commandLine, m_chordRun -> m_tokens, " ");
        if (m_chordRun -> m_tokens.size() == 0)
        {
          NS_LOG_INFO ("Failed to Tokenize");
          continue;
        }
        //check for time command
        std::vector<std::string>::iterator iterator = m_chordRun -> m_tokens.begin();
        if (*iterator == "Time")
        {
          if (m_chordRun -> m_tokens.size() < 2)
          {
            continue;
          }
          iterator++;
          std::istringstream sin (*iterator);
          uint64_t delta;
          sin >> delta;
          time = MilliSeconds( time.GetMilliSeconds() + delta);
          std::cout << "Time Pointer: " << time.GetMilliSeconds() << std::endl;
          m_chordRun -> m_tokens.clear();
          continue;
        }
        NS_LOG_INFO ("Processing...");
        m_chordRun->ProcessCommandTokens (m_chordRun -> m_tokens, MilliSeconds(time.GetMilliSeconds()));
        m_chordRun -> m_tokens.clear();
      }
    }
  }

    Simulator::Schedule (MilliSeconds (200), &ChordRun::ReadCommandTokens, this);

   if (pthread_create (&commandHandlerThreadId, NULL, ChordRun::CommandHandler, &th_argument) != 0)
   {
     perror ("New Thread Creation Failed, Exiting...");
     exit (1);
   }
 }

void
ChordRun::Stop ()
{

  NS_LOG_FUNCTION_NOARGS();
  //Cancel keyboard thread
  pthread_cancel (commandHandlerThreadId);
  //Join keyboard thread
  pthread_join (commandHandlerThreadId, NULL);
}


void*
ChordRun::CommandHandler (void *arg)
{
  struct CommandHandlerArgument th_argument = *((struct CommandHandlerArgument *) arg);
  std::string scriptFile = th_argument.scriptFile;
  NodeContainer nodeContainer = th_argument.nodeContainer;
  ChordRun* chordRun = (ChordRun *)th_argument.chordRun;

  chordRun -> m_chordRun = chordRun;
  chordRun -> m_nodeContainer = nodeContainer;
  chordRun -> m_scriptFile = scriptFile;

  while (1)
  {
    std::string commandLine;
    //read command from keyboard
    std::cout << "\nCommand > ";
    std::getline(std::cin, commandLine, '\n');
    if (chordRun->m_readyToRead == true)
    {
      std::cout << "Simulator busy, please try again..\n";
      continue;
    }

    chordRun->Tokenize (commandLine, chordRun -> m_tokens, " ");

    std::vector<std::string>::iterator iterator = chordRun -> m_tokens.begin();

    if (chordRun -> m_tokens.size() == 0)
    {
      continue;
    }
    //check for quit
    else if (*iterator == "quit")
    {
      break;
    }
    chordRun -> m_readyToRead = true;

    //SINGLE THREADED SIMULATOR WILL CRASH, so let simulator schedule processcommandtokens!
    //chordRun->ProcessCommandTokens (tokens, MilliSeconds (0.));

  }
  Simulator::Stop ();
  pthread_exit (NULL);
}

void
ChordRun::ReadCommandTokens (void)
{
  if (m_readyToRead == true)
  {

    if (m_tokens.size() > 0)
    {
      m_chordRun->ProcessCommandTokens (m_tokens, MilliSeconds (0.0));
    }
    m_tokens.clear();
    m_readyToRead = false;
  }
  Simulator::Schedule (MilliSeconds (200), &ChordRun::ReadCommandTokens, this);

}

void
ChordRun::ProcessCommandTokens (std::vector<std::string> tokens, Time time)
{
  NS_LOG_INFO ("Processing Command Token...");
  //Process tokens
  std::vector<std::string>::iterator iterator = tokens.begin();

  std::istringstream sin (*iterator);
  uint16_t nodeNumber;
  sin >> nodeNumber;
  //this command can be in script file
  if (*iterator == "quit")
  {
    NS_LOG_INFO ("Scheduling Command quit...");
    Simulator::Stop (MilliSeconds(time.GetMilliSeconds()));
    return;
  }
  else if (tokens.size() < 2)
  {
    return;
  }
  Ptr<ChordIpv4> chordApplication = m_nodeContainer.Get(nodeNumber)->GetApplication(0)->GetObject<ChordIpv4> ();

  iterator++;
  if (*iterator == "InsertVNode")
  {
    if (tokens.size() < 3)
    { 
      return;
    }
    //extract node name
    iterator++;
    std::string vNodeName = std::string(*iterator);
    NS_LOG_INFO ("Scheduling Command InsertVNode...");
    Simulator::Schedule (MilliSeconds(time.GetMilliSeconds()), &ChordRun::InsertVNode, this, chordApplication, vNodeName);
    return;
  }
  else if (*iterator == "DumpVNodeInfo")
  {
    if (tokens.size() < 3)
    { 
      return;
    }
    //extract node name
    iterator++;
    std::string vNodeName = std::string(*iterator);
    NS_LOG_INFO ("Scheduling Command DumpVNodeInfo...");
    Simulator::Schedule (MilliSeconds(time.GetMilliSeconds()), &ChordRun::DumpVNodeInfo, this,chordApplication,vNodeName);
  }

  else if (*iterator == "DumpDHashInfo")
  {
    NS_LOG_INFO ("Scheduling Command DumpDHashInfo...");
    Simulator::Schedule (MilliSeconds(time.GetMilliSeconds()), &ChordRun::DumpDHashInfo, this, chordApplication);
  }

  else if (*iterator == "TraceRing")
  {
    if (tokens.size() < 3)
    { 
      return;
    }
    //extract node name
    iterator++;
    std::string vNodeName = std::string(*iterator);
    NS_LOG_INFO ("Scheduling Command TraceRing...");
    Simulator::Schedule (MilliSeconds(time.GetMilliSeconds()), &ChordIpv4::FireTraceRing, chordApplication, vNodeName);
  }
  else if (*iterator == "Lookup")
  {
    if (tokens.size() < 3)
    {
      return;
    }
    //extract node resourceName
    iterator++;
    std::string resourceName = std::string(*iterator);
    Simulator::Schedule (MilliSeconds(time.GetMilliSeconds()), &ChordRun::Lookup, this, chordApplication, resourceName);
    return;
  }
  else if (*iterator == "Retrieve")
  {
    if (tokens.size() < 3)
    {
      return;
    }
    iterator++;
    std::string resourceName = std::string(*iterator);
    Simulator::Schedule (MilliSeconds(time.GetMilliSeconds()), &ChordRun::Retrieve, this, chordApplication, resourceName);
  }
  else if (*iterator == "RemoveVNode")
  {
    if (tokens.size() < 3)
    {
      return;
    }
    //extract node resourceName
    iterator++;
    std::string vNodeName = std::string(*iterator);
    NS_LOG_INFO ("Scheduling Command RemoveVNode...");
    Simulator::Schedule (MilliSeconds(time.GetMilliSeconds()), &ChordIpv4::RemoveVNode, chordApplication, vNodeName);
  }
  else if (*iterator == "Detach")
  {
    NS_LOG_INFO ("Scheduling Command Detach...");
    Simulator::Schedule (MilliSeconds(time.GetMilliSeconds()), &ChordRun::DetachNode, this, nodeNumber);
  }
  else if (*iterator == "ReAttach")
  {
    NS_LOG_INFO ("Scheduling Command ReAttach...");	
    Simulator::Schedule (MilliSeconds(time.GetMilliSeconds()), &ChordRun::ReAttachNode, this, nodeNumber);
  }
  else if (*iterator == "Crash")
  {
    NS_LOG_INFO ("Scheduling Command Crash");
    Simulator::Schedule (MilliSeconds(time.GetMilliSeconds()), &ChordRun::CrashChord, this, chordApplication);
  }
  else if (*iterator == "Restart")
  {
    NS_LOG_INFO ("Scheduling Command Restart...");
    Simulator::Schedule (MilliSeconds(time.GetMilliSeconds()), &ChordRun::RestartChord, this, chordApplication);
  }
  else if (*iterator == "FixFinger")
  {
    iterator++;
    std::string vNodeName = std::string (*iterator);
    NS_LOG_INFO ("Scheduling Command FixFinger...");
    Simulator::Schedule (MilliSeconds(time.GetMilliSeconds()), &ChordIpv4::FixFingers, chordApplication, vNodeName);
  }
  else if (*iterator == "Insert")
  {
    if (tokens.size() < 4)
    {
      return;
    }
    iterator++;
    std::string resourceName = std::string(*iterator);

    iterator++;
    std::string resourceValue = std::string (*iterator);
    NS_LOG_INFO ("Scheduling Command Insert...");
    Simulator::Schedule (MilliSeconds(time.GetMilliSeconds()), &ChordRun::Insert, this, chordApplication, resourceName, resourceValue);
  }
  else
  {
    std::cout << "Unrecognized command\n";
  }
}

void
ChordRun::InsertVNode(Ptr<ChordIpv4> chordApplication, std::string vNodeName)
{
  NS_LOG_FUNCTION_NOARGS();
  std::cout << "\nCurrent Simulation Time: " << Simulator::Now ().GetMilliSeconds() << std::endl;
  unsigned char* md = (unsigned char*) malloc (20);
  const unsigned char* message = (const unsigned char*) vNodeName.c_str();
  ZEN_LIB::sha1 (message , vNodeName.length() , md);

  NS_LOG_INFO ("Scheduling Command InsertVNode...");
  chordApplication->InsertVNode(vNodeName, md, 20);
  free (md);
}

void
ChordRun::Lookup (Ptr<ChordIpv4> chordApplication, std::string resourceName)
{
  NS_LOG_FUNCTION_NOARGS();
  std::cout << "\nCurrent Simulation Time: " << Simulator::Now ().GetMilliSeconds() << std::endl;
  unsigned char* md = (unsigned char*) malloc (20);
  const unsigned char* message = (const unsigned char*) resourceName.c_str();
  ZEN_LIB::sha1 (message , resourceName.length() , md);
  NS_LOG_INFO ("Scheduling Command Lookup...");
  chordApplication->LookupKey(md, 20);
  free (md);
}

void
ChordRun::Insert (Ptr<ChordIpv4> chordApplication, std::string resourceName, std::string resourceValue)
{
  NS_LOG_FUNCTION_NOARGS();
  std::cout << "\nCurrent Simulation Time: " << Simulator::Now ().GetMilliSeconds() << std::endl;
  NS_LOG_INFO ("Insert ResourceName : "<< resourceName );
  NS_LOG_INFO ("Insert Resourcevalue : "<< resourceValue);
  unsigned char* md = (unsigned char*) malloc (20);
  const unsigned char* message = (const unsigned char*) resourceName.c_str();
  ZEN_LIB::sha1 (message , resourceName.length() , md);
  unsigned char* value = (unsigned char *)(resourceValue.c_str());
  chordApplication->Insert(md, 20, value, resourceValue.length());
  free (md);
}

void
ChordRun::Retrieve (Ptr<ChordIpv4> chordApplication, std::string resourceName)
{
  NS_LOG_FUNCTION_NOARGS();
  std::cout << "\nCurrent Simulation Time: " << Simulator::Now ().GetMilliSeconds() << std::endl;
  unsigned char* md = (unsigned char*) malloc (20);
  const unsigned char* message = (const unsigned char*) resourceName.c_str();
  ZEN_LIB::sha1 (message , resourceName.length() , md);
  chordApplication->Retrieve (md, 20);
  free (md);
}

void
ChordRun::DetachNode(uint16_t nodeNumber)
{
  NS_LOG_FUNCTION_NOARGS();
  std::cout << "\nCurrent Simulation Time: " << Simulator::Now ().GetMilliSeconds() << std::endl;
  Ptr<NetDevice> netDevice = m_nodeContainer.Get(nodeNumber)->GetDevice(1);
  Ptr<CsmaChannel> channel = netDevice->GetChannel()->GetObject<CsmaChannel> ();
  channel->Detach(nodeNumber);
}

void
ChordRun::ReAttachNode(uint16_t nodeNumber)
{
  NS_LOG_FUNCTION_NOARGS();
  std::cout << "\nCurrent Simulation Time: " << Simulator::Now ().GetMilliSeconds() << std::endl;
  Ptr<NetDevice> netDevice = m_nodeContainer.Get(nodeNumber)->GetDevice(1);
  Ptr<CsmaChannel> channel = netDevice->GetChannel()->GetObject<CsmaChannel> ();
  if (channel->Reattach(nodeNumber) == false)
    std::cout << "Reattach success" << std::endl;
  else
    std::cout << "Reattach failed" << std::endl;
}

void
ChordRun::CrashChord(Ptr<ChordIpv4> chordApplication)
{
  NS_LOG_FUNCTION_NOARGS();
  std::cout << "\nCurrent Simulation Time: " << Simulator::Now ().GetMilliSeconds() << std::endl;
  /* This code used to work in ns-3.6 release */
  //chordApplication -> Stop(Seconds(0.0));
}

void
ChordRun::RestartChord(Ptr<ChordIpv4> chordApplication)
{
  NS_LOG_FUNCTION_NOARGS();
  std::cout << "\nCurrent Simulation Time: " << Simulator::Now ().GetMilliSeconds() << std::endl;
  /* This code used to work in ns-3.6 release */
  //chordApplication -> Start(Seconds(0.0));
}
void
ChordRun::DumpVNodeInfo(Ptr<ChordIpv4> chordApplication,std::string vNodeName)
{
  NS_LOG_FUNCTION_NOARGS();
  std::cout << "\nCurrent Simulation Time: " << Simulator::Now ().GetMilliSeconds() << std::endl;
  chordApplication->DumpVNodeInfo (vNodeName, std::cout);
}

void
ChordRun::DumpDHashInfo (Ptr<ChordIpv4> chordApplication)
{
  NS_LOG_FUNCTION_NOARGS();
  std::cout << "\nCurrent Simulation Time: " << Simulator::Now ().GetMilliSeconds() << std::endl;
  chordApplication->DumpDHashInfo (std::cout);
}

void
ChordRun::JoinSuccess (std::string vNodeName, uint8_t* key, uint8_t numBytes)
{
  NS_LOG_FUNCTION_NOARGS();
  std::cout << "\nCurrent Simulation Time: " << Simulator::Now ().GetMilliSeconds() << std::endl;
  std::cout << "VNode: " << vNodeName << " Joined successfully" << std::endl;
  PrintHexArray (key, numBytes, std::cout);
}

void
ChordRun::LookupSuccess (uint8_t* lookupKey, uint8_t lookupKeyBytes, Ipv4Address ipAddress, uint16_t port)
{
  NS_LOG_FUNCTION_NOARGS();
  std::cout << "\nCurrent Simulation Time: " << Simulator::Now ().GetMilliSeconds() << std::endl;
  std::cout << "Lookup Success Ip: " << ipAddress << " Port: " << port << std::endl;
  PrintHexArray (lookupKey, lookupKeyBytes, std::cout);
}

void
ChordRun::LookupFailure (uint8_t* lookupKey, uint8_t lookupKeyBytes)
{ 
  NS_LOG_FUNCTION_NOARGS();
  std::cout << "\nCurrent Simulation Time: " << Simulator::Now ().GetMilliSeconds() << std::endl;
  std::cout << "Key Lookup failed" << std::endl;
  PrintHexArray (lookupKey, lookupKeyBytes, std::cout);
}

void
ChordRun::VNodeKeyOwnership (std::string vNodeName, uint8_t* key, uint8_t keyBytes, uint8_t* predecessorKey, uint8_t predecessorKeyBytes, uint8_t* oldPredecessorKey, uint8_t oldPredecessorKeyBytes, Ipv4Address predecessorIp, uint16_t predecessorPort)
{
  NS_LOG_FUNCTION_NOARGS();
  std::cout << "\nCurrent Simulation Time: " << Simulator::Now ().GetMilliSeconds() << std::endl;
  std::cout << "VNode: " << vNodeName << " Key Space Ownership change reported" << std::endl;
  std::cout << "New predecessor Ip: " << predecessorIp << " Port: " << predecessorPort << std::endl;
}


void
ChordRun::VNodeFailure (std::string vNodeName, uint8_t* key, uint8_t numBytes)
{
  NS_LOG_FUNCTION_NOARGS();
  std::cout << "\nCurrent Simulation Time: " << Simulator::Now ().GetMilliSeconds() << std::endl;
  std::cout << "VNode: " << vNodeName << " Failed" << std::endl;
}

void
ChordRun::InsertSuccess (uint8_t* key, uint8_t numBytes, uint8_t* object, uint32_t objectBytes)
{ 
  NS_LOG_FUNCTION_NOARGS();
  std::cout << "\nCurrent Simulation Time: " << Simulator::Now ().GetMilliSeconds() << std::endl;
  std::cout << "Insert Success!";
  PrintHexArray (key, numBytes, std::cout);
  PrintCharArray (object, objectBytes, std::cout);
}

void
ChordRun::RetrieveSuccess (uint8_t* key, uint8_t numBytes, uint8_t* object, uint32_t objectBytes)
{ 
  NS_LOG_FUNCTION_NOARGS();
  std::cout << "\nCurrent Simulation Time: " << Simulator::Now ().GetMilliSeconds() << std::endl;
  std::cout << "Retrieve Success!";
  PrintHexArray (key, numBytes, std::cout);
  PrintCharArray (object, objectBytes, std::cout);
}

void
ChordRun::InsertFailure (uint8_t* key, uint8_t numBytes, uint8_t* object, uint32_t objectBytes)
{
  NS_LOG_FUNCTION_NOARGS();
  std::cout << "\nCurrent Simulation Time: " << Simulator::Now ().GetMilliSeconds() << std::endl;
  std::cout << "Insert Failure Reported...";
  PrintHexArray (key, numBytes, std::cout);
  PrintCharArray (object, objectBytes, std::cout);
}

void
ChordRun::RetrieveFailure (uint8_t* key, uint8_t keyBytes)
{
  NS_LOG_FUNCTION_NOARGS();
  std::cout << "\nCurrent Simulation Time: " << Simulator::Now ().GetMilliSeconds() << std::endl;
  std::cout << "Retrieve Failure Reported...";
  PrintHexArray (key, keyBytes, std::cout);
}


void
ChordRun::TraceRing (std::string vNodeName, uint8_t* key, uint8_t numBytes)
{
  std::cout << "<" << vNodeName << ">" << std::endl;
}


void 
ChordRun::Tokenize(const std::string& str,
    std::vector<std::string>& tokens,
    const std::string& delimiters)
{
  // Skip delimiters at beginning.
  std::string::size_type lastPos = str.find_first_not_of(delimiters, 0);
  // Find first "non-delimiter".
  std::string::size_type pos = str.find_first_of(delimiters, lastPos);

  while (std::string::npos != pos || std::string::npos != lastPos)
  {
    // Found a token, add it to the vector.
    tokens.push_back(str.substr(lastPos, pos - lastPos));
    // Skip delimiters.  Note the "not_of"
    lastPos = str.find_first_not_of(delimiters, pos);
    // Find next "non-delimiter"
    pos = str.find_first_of(delimiters, lastPos);
  }
}

void
ChordRun::PrintCharArray (uint8_t* array, uint32_t size, std::ostream &os)
{
  os << "Char Array: ";
  for (uint32_t i = 0; i<size; i++)
    os << array[i];
  os << "\n";
}

void
ChordRun::PrintHexArray (uint8_t* array, uint32_t size, std::ostream &os)
{
  os << "Bytes: " << (uint16_t) size << "\n";
  os << "Array: \n";
  os << "[ ";
  for (uint8_t j=0;j<size;j++)
  {
    os << std::hex << "0x" <<(uint16_t) array[j] << " ";
  }
  os << std::dec << "]\n";
}

 int 
 main (int argc, char *argv[])
 {
   uint16_t nodes;
   uint16_t bootStrapNodeNum;
   std::string scriptFile = "";
   if (argc < 3)
   {
     std::cout << "Usage: chord-run <nodes> <bootstrapNodeNumber> <OPTIONAL: script-file>. Please input number of nodes to simulate and bootstrap node number\n";
    exit (1);
   }
   else
   {
    nodes = atoi(argv[1]);
    bootStrapNodeNum = atoi(argv[2]);
    if (argc == 4)
    {
      scriptFile = argv[3];
    }
    std::cout << "Number of nodes to simulate: " << (uint16_t) nodes << "\n";
   }

   LogComponentEnable ("ChordRun", LOG_LEVEL_ALL);
   LogComponentEnable("ChordIpv4Application", LOG_LEVEL_ERROR);
   //LogComponentEnable("UdpSocketImpl", LOG_LEVEL_ALL);
   //LogComponentEnable("Packet", LOG_LEVEL_ALL);
   //LogComponentEnable("Socket", LOG_LEVEL_ALL);
   //LogComponentEnable("ChordMessage", LOG_LEVEL_ALL);
   LogComponentEnable("ChordIdentifier", LOG_LEVEL_ERROR);
   LogComponentEnable("ChordTransaction", LOG_LEVEL_ERROR);
   LogComponentEnable("ChordVNode", LOG_LEVEL_ERROR);
   LogComponentEnable("ChordNodeTable", LOG_LEVEL_ERROR);
   LogComponentEnable("DHashIpv4", LOG_LEVEL_ERROR);
   LogComponentEnable("DHashConnection", LOG_LEVEL_ERROR);
   //LogComponentEnable("TcpSocketImpl", LOG_LEVEL_ALL);
   //LogComponentEnable("TcpL4Protocol", LOG_LEVEL_ALL);

   //
   // Allow the user to override any of the defaults and the above Bind() at
   // run-time, via command-line arguments
   //
   CommandLine cmd;
   cmd.Parse (argc, argv);
   //
   // Explicitly create the nodes required by the topology (shown above).
   //

   NS_LOG_INFO ("Creating nodes.");
   NodeContainer nodeContainer;
   nodeContainer.Create (nodes);

   InternetStackHelper internet;
   internet.Install (nodeContainer);

   NS_LOG_INFO ("Create channels.");
   //
   // Explicitly create the channels required by the topology (shown above).
   //
   CsmaHelper csma;
   csma.SetChannelAttribute ("DataRate", StringValue ("100Mbps"));
   csma.SetChannelAttribute ("Delay", TimeValue (NanoSeconds (6560)));
   csma.SetDeviceAttribute ("Mtu", UintegerValue (1400));
   NetDeviceContainer d = csma.Install (nodeContainer);

   Ipv4AddressHelper ipv4;
   //
   // We've got the "hardware" in place.  Now we need to add IP addresses.
   //
   NS_LOG_INFO ("Assign IP Addresses.");
   ipv4.SetBase ("10.1.1.0", "255.255.255.0");
   Ipv4InterfaceContainer i = ipv4.Assign (d);

   NS_LOG_INFO ("Create Applications.");
   //
   //Create a command handler thread
   //
   ChordRun chordRun;
   //
   // Create a ChordIpv4 application on all nodes. Insertion of vnodes controlled by user via keyboard.
   //

   uint16_t port = 2000;
   for (int j=0; j<nodes; j++)
   {
     ChordIpv4Helper server (i.GetAddress(bootStrapNodeNum), port, i.GetAddress(j), port, port+1, port+2);
     ApplicationContainer apps = server.Install (nodeContainer.Get(j));
     apps.Start(Seconds (0.0));
     Ptr<ChordIpv4> chordApplication = nodeContainer.Get(j)->GetApplication(0)->GetObject<ChordIpv4> ();
     chordApplication->SetJoinSuccessCallback (MakeCallback(&ChordRun::JoinSuccess, &chordRun));
     chordApplication->SetLookupSuccessCallback (MakeCallback(&ChordRun::LookupSuccess, &chordRun));
     chordApplication->SetLookupFailureCallback (MakeCallback(&ChordRun::LookupFailure, &chordRun));
     chordApplication->SetTraceRingCallback (MakeCallback(&ChordRun::TraceRing, &chordRun));
     chordApplication->SetVNodeFailureCallback(MakeCallback(&ChordRun::VNodeFailure, &chordRun));
     chordApplication->SetVNodeKeyOwnershipCallback(MakeCallback(&ChordRun::VNodeKeyOwnership, &chordRun));
     //DHash configuration:: Needs to be done once but can be overwritten...
     chordApplication->SetInsertSuccessCallback (MakeCallback(&ChordRun::InsertSuccess, &chordRun));
     chordApplication->SetRetrieveSuccessCallback (MakeCallback(&ChordRun::RetrieveSuccess, &chordRun));
     chordApplication->SetInsertFailureCallback (MakeCallback(&ChordRun::InsertFailure, &chordRun));
     chordApplication->SetRetrieveFailureCallback (MakeCallback(&ChordRun::RetrieveFailure, &chordRun));
   }

   //Start Chord-Run 
   chordRun.Start(scriptFile,nodeContainer);
   //
   // Now, do the actual simulation.
   //
   NS_LOG_INFO ("Run Simulation.");
   Simulator::Run ();
   chordRun.Stop ();
   Simulator::Destroy ();
   NS_LOG_INFO ("Done.");
   return 0;

 }



