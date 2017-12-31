/**
 * C-Ares fuzzer
 *
 * Compile library with ASAN:
 * $ curl -fSsL https://c-ares.haxx.se/download/c-ares-1.13.0.tar.gz  | tar xfz - && cd c-ares-1.13.0
 * $ ./configure CC="clang-5.0 -O2 -fno-omit-frame-pointer -g -fsanitize=address -fsanitize-coverage=trace-pc-guard,trace-cmp,trace-gep,trace-div"
 *
 * Compile fuzzer with:
 * $ ./make.sh c-ares-fuzzer.cc -Ic-ares-1.13.0 -Lc-ares-1.13.0 -lcares
 *
 * Run fuzzer with:
 * $ ./c-ares-fuzzer -workers=4 -jobs=4 -timeout=3000 -rss_limit_mb=256
 */

#include <stdint.h>
#include <stdlib.h>
#include <arpa/nameser.h>
#include <ares.h>
#include <alloca.h>
#include <string.h>
#include <stdio.h>

static void callback(void *arg, int status, int timeouts, struct hostent *host){}
static void state_cb(void *data, int s, int read, int write){}

extern "C" int LLVMFuzzerTestOneInput(const uint* data, size_t size)
{

        if (size<=2)
                return 0;
/*
        char* name = (char*)alloca(size);
        if(!name)
                return 0;
        memcpy(name, data, size);
*/
        unsigned char *buf;
        int buflen;

        int res = ares_create_query(
                                (const char *)data,     // name
                                ns_c_in,  // dnsclass
                                ns_t_a,   // type
                                1337,     // id
                                0,        // rd
                                &buf,     // buf
                                &buflen,  // buflen
                                0);       // max_udp_len
        if (res == ARES_SUCCESS)
                ares_free_string(buf);

/*

        ares_channel channel;
        int status;
        struct ares_options options;
        int optmask = 0;

        status = ares_library_init(ARES_LIB_INIT_ALL);
        if (status != ARES_SUCCESS) return 0;
        options.sock_state_cb = state_cb;
        optmask |= ARES_OPT_SOCK_STATE_CB;
        status = ares_init_options(&channel, &options, optmask);
        if(status != ARES_SUCCESS) return 0;
        if(size == 0) return 0;
        ares_gethostbyname(channel, name, AF_INET, callback, NULL);
        ares_destroy(channel);
        ares_library_cleanup();
*/
/*
  unsigned char *buf;
  int buflen;
  std::string s(reinterpret_cast<const char *>(data), size);
  ares_create_query(s.c_str(), ns_c_in, ns_t_a, 0x1234, 0, &buf, &buflen, 0);
  ares_free_string(buf);
*/
        return 0;
}
