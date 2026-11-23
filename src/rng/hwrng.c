/*
 * This file is part of the Pico Keys SDK distribution (https://github.com/polhenarejos/pico-keys-sdk).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include "picokeys.h"
#include "hwrng.h"
#include "pico_time.h"
#include "mbedtls/hmac_drbg.h"
#include "mbedtls/md.h"
#include "mbedtls/platform_util.h"

#if defined(PICO_PLATFORM)
#include "pico/rand.h"
#include "pico/mutex.h"
#if defined(PICO_RP2040) && PICO_RP2040
#include "hardware/structs/rosc.h"
#include "hardware/timer.h"
#endif
#elif defined(ESP_PLATFORM)
#include "bootloader_random.h"
#include "esp_random.h"
#include "compat/esp_compat.h"
#else
#include "compat/queue.h"
#endif

static void hwrng_start(void) {
#if defined(ENABLE_EMULATION)
    srand((unsigned int)time(NULL));
#elif defined(ESP_PLATFORM)
    bootloader_random_enable();
#endif
}

#define HWRNG_NOISE_BLOCK_SIZE 64   // 512 raw noise bits per block
#define HWRNG_SEED_BLOCKS      16   // 8192 raw noise bits at boot
#define HWRNG_SEED_ATTEMPTS    8    // Retries before a stuck source stops the boot
#define HWRNG_MIN_TRANSITIONS  16   // A live source changes value within a block
#define HWRNG_OUTPUT_SIZE      32
#define HWRNG_ROSC_SAMPLE_US   10   // Spacing between ring oscillator samples

static mbedtls_hmac_drbg_context hwrng_drbg;

/* Never hand out key material from a generator that could not be seeded. */
static void hwrng_fail(void) {
#if defined(PICO_PLATFORM)
    panic("hwrng: entropy source failed");
#else
    abort();
#endif
}

static uint8_t hwrng_noise_bit(void) {
#if defined(PICO_RP2040) && PICO_RP2040
    return (uint8_t)(rosc_hw->randombit & 1u);
#elif defined(PICO_PLATFORM)
    return (uint8_t)(get_rand_32() & 1u); // RP2350: backed by the hardware TRNG
#elif defined(ESP_PLATFORM)
    return (uint8_t)(esp_random() & 1u);
#else
    return (uint8_t)(rand() & 1);
#endif
}

static void hwrng_read_noise(uint8_t *out, size_t len) {
    for (size_t i = 0; i < len; i++) {
        uint8_t value = 0;

        for (int bit = 0; bit < 8; bit++) {
#if defined(PICO_RP2040) && PICO_RP2040
            busy_wait_us_32(HWRNG_ROSC_SAMPLE_US);
#endif
            value = (uint8_t)((value << 1) | hwrng_noise_bit());
        }
        out[i] = value;
    }
}

/* Catches a dead or stuck source. It does not estimate how random the bits are. */
static bool hwrng_noise_is_live(const uint8_t *block, size_t len) {
    unsigned transitions = 0;
    uint8_t previous = block[0] >> 7;

    for (size_t i = 0; i < len; i++) {
        for (int bit = 7; bit >= 0; bit--) {
            uint8_t current = (block[i] >> bit) & 1u;

            transitions += current != previous;
            previous = current;
        }
    }
    return transitions >= HWRNG_MIN_TRANSITIONS;
}

static void hwrng_read_live_block(uint8_t block[HWRNG_NOISE_BLOCK_SIZE]) {
    for (int attempt = 0; attempt < HWRNG_SEED_ATTEMPTS; attempt++) {
        hwrng_read_noise(block, HWRNG_NOISE_BLOCK_SIZE);
        if (hwrng_noise_is_live(block, HWRNG_NOISE_BLOCK_SIZE)) {
            return;
        }
    }
    hwrng_fail();
}

/* Conditions raw hardware noise through HMAC-SHA-256 before any output exists. */
static void hwrng_seed(void) {
    uint8_t block[HWRNG_NOISE_BLOCK_SIZE];
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    mbedtls_hmac_drbg_init(&hwrng_drbg);
    hwrng_read_live_block(block);
#if defined(PICO_PLATFORM)
    /* The SDK generator adds startup RAM, the chip ID and boot timing. */
    for (size_t i = 0; i + sizeof(uint64_t) <= sizeof(block); i += sizeof(uint64_t)) {
        uint64_t word = get_rand_64();

        for (size_t j = 0; j < sizeof(word); j++) {
            block[i + j] ^= (uint8_t)(word >> (8 * j));
        }
    }
#endif
    if (md == NULL || mbedtls_hmac_drbg_seed_buf(&hwrng_drbg, md, block, sizeof(block)) != 0) {
        hwrng_fail();
    }
    for (int i = 0; i < HWRNG_SEED_BLOCKS; i++) {
        hwrng_read_live_block(block);
        if (mbedtls_hmac_drbg_update(&hwrng_drbg, block, sizeof(block)) != 0) {
            hwrng_fail();
        }
    }
    mbedtls_platform_zeroize(block, sizeof(block));
}

/* Keeps mixing one fresh noise bit per millisecond into the generator. */
static void hwrng_collect_noise(void) {
    static uint8_t block[HWRNG_NOISE_BLOCK_SIZE];
    static size_t bits = 0;
    static uint32_t last_ms = 0;
    uint32_t now = board_millis();

    if (now == last_ms) {
        return;
    }
    last_ms = now;
    block[bits / 8] = (uint8_t)((block[bits / 8] << 1) | hwrng_noise_bit());
    if (++bits == sizeof(block) * 8) {
        if (mbedtls_hmac_drbg_update(&hwrng_drbg, block, sizeof(block)) != 0) {
            hwrng_fail();
        }
        mbedtls_platform_zeroize(block, sizeof(block));
        bits = 0;
    }
}

typedef struct hwrng_buf {
    uint8_t *buf;
    size_t head;
    size_t tail;
    size_t size;
    size_t count;
} hwrng_buf_t;

static mutex_t hwrng_mutex;
static bool hwrng_mutex_initialized = false;

static inline void hwrng_lock(void) {
    if (hwrng_mutex_initialized) {
        mutex_enter_blocking(&hwrng_mutex);
    }
}

static inline void hwrng_unlock(void) {
    if (hwrng_mutex_initialized) {
        mutex_exit(&hwrng_mutex);
    }
}

static void hwrng_buf_init(struct hwrng_buf *rb, byte_array_t buffer) {
    rb->buf = buffer.data;
    rb->size = buffer.len;
    rb->head = rb->tail = 0;
    rb->count = 0;
}

static size_t hwrng_buf_add(struct hwrng_buf *rb, const_byte_array_t data) {
    size_t room = rb->size - rb->count;
    size_t n = data.len < room ? data.len : room;
    size_t tail = rb->tail;
    size_t first = n;

    if (first > rb->size - tail) {
        first = rb->size - tail;
    }
    if (first) {
        memcpy(rb->buf + tail, data.data, first);
        tail += first;
        if (tail >= rb->size) {
            tail = 0;
        }
    }
    if (n > first) {
        size_t second = n - first;
        memcpy(rb->buf + tail, data.data + first, second);
        tail += second;
    }
    rb->tail = tail;
    rb->count += n;
    return n;
}

static size_t hwrng_buf_del(struct hwrng_buf *rb, byte_array_t data) {
    size_t n = data.len < rb->count ? data.len : rb->count;
    size_t head = rb->head;
    size_t first = n;

    if (first > rb->size - head) {
        first = rb->size - head;
    }
    if (first) {
        memcpy(data.data, rb->buf + head, first);
        head += first;
        if (head >= rb->size) {
            head = 0;
        }
    }
    if (n > first) {
        size_t second = n - first;
        memcpy(data.data + first, rb->buf + head, second);
        head += second;
    }
    rb->head = head;
    rb->count -= n;
    return n;
}

static inline size_t hwrng_buf_space(const struct hwrng_buf *rb) {
    return rb->size - rb->count;
}

static inline bool hwrng_buf_full(const struct hwrng_buf *rb) {
    return rb->count == rb->size;
}

static struct hwrng_buf ring_buffer;

void *hwrng_task(void) {
    struct hwrng_buf *rb = &ring_buffer;

    hwrng_lock();
    hwrng_collect_noise();
    if (hwrng_buf_space(rb) >= HWRNG_OUTPUT_SIZE) {
        uint8_t output[HWRNG_OUTPUT_SIZE];

        if (mbedtls_hmac_drbg_random(&hwrng_drbg, output, sizeof(output)) != 0) {
            hwrng_fail();
        }
        hwrng_buf_add(rb, CONST_BYTE_ARRAY(output, sizeof(output)));
        mbedtls_platform_zeroize(output, sizeof(output));
    }
    hwrng_unlock();
    return NULL;
}

void hwrng_init(byte_array_t buffer) {
    struct hwrng_buf *rb = &ring_buffer;

    mutex_init(&hwrng_mutex);
    hwrng_mutex_initialized = true;
    hwrng_buf_init(rb, buffer);

    hwrng_start();

    hwrng_seed();
}

size_t hwrng_read(byte_array_t buffer) {
    struct hwrng_buf *rb = &ring_buffer;
    size_t n;

    hwrng_lock();
    n = hwrng_buf_del(rb, buffer);
    hwrng_unlock();
    return n;
}

void hwrng_flush(void) {
    struct hwrng_buf *rb = &ring_buffer;
    hwrng_lock();
    rb->head = 0;
    rb->tail = 0;
    rb->count = 0;
    hwrng_unlock();
}

uint32_t hwrng_get(void) {
    uint32_t v = 0;
    size_t offset = 0;

    while (offset < sizeof(v)) {
        size_t n = hwrng_read(BYTE_ARRAY(((uint8_t *)&v) + offset, sizeof(v) - offset));
        if (n == 0) {
            hwrng_task();
            continue;
        }
        offset += n;
    }

    return v;
}

void hwrng_wait_full(void) {
    struct hwrng_buf *rb = &ring_buffer;
#ifdef ESP_PLATFORM
    uint8_t core = xTaskGetCurrentTaskHandle() == hcore1 ? 1 : 0;
#elif defined(PICO_PLATFORM)
    uint core = get_core_num();
#endif
    while (true) {
        hwrng_lock();
        bool full = hwrng_buf_full(rb);
        hwrng_unlock();
        if (full) {
            break;
        }
#if defined(PICO_PLATFORM) || defined(ESP_PLATFORM)
        if (core == 1) {
            sleep_ms(1);
        }
        else
#endif
        hwrng_task();
    }
}
