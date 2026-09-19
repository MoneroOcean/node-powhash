{
    "targets": [
        {
            "target_name": "node-powhash",
             'conditions': [
                ['OS=="mac"', {
                  'defines': [
                    'XMRIG_OS_APPLE',
                    'XMRIG_OS_MACOS'
                  ],
                  'xcode_settings': {
                    'GCC_ENABLE_CPP_EXCEPTIONS': 'YES'
                  }
                }],
                ['target_arch=="arm64"', {
                  'defines': [
                    'XMRIG_ARM=8'
                  ],
                  'cflags_c': [
                    '-march=armv8-a+crypto',
                    '-flax-vector-conversions'
                  ],
                  'cflags_cc': [
                    '-march=armv8-a+crypto',
                    '-flax-vector-conversions'
                  ]
                }],
                ['target_arch=="arm"', {
                  'defines': [
                    'XMRIG_ARM=7'
                  ],
                  'cflags_c': [
                    '-mfpu=neon',
                    '-flax-vector-conversions'
                  ],
                  'cflags_cc': [
                    '-mfpu=neon',
                    '-flax-vector-conversions'
                  ]
                }],
                ['target_arch!="arm64" and target_arch!="arm"', {
                  'defines': [
                    'XMRIG_FEATURE_ASM'
                  ],
                  'cflags_c': [
                    '-march=native'
                  ],
                  'cflags_cc': [
                    '-march=native'
                  ]
                }]
              ],
            "sources": [
                '<!@(uname -m | grep "^x86_64$" >/dev/null && echo "xmrig/crypto/cn/asm/cn_main_loop.S" || echo)',
                '<!@(uname -m | grep "^x86_64$" >/dev/null && echo "xmrig/crypto/cn/asm/CryptonightR_template.S" || echo)',
                '<!@(uname -m | grep "^x86_64$" >/dev/null && echo "xmrig/crypto/cn/r/CryptonightR_gen.cpp" || echo)',
                '<!@(uname -m | grep "^x86_64$" >/dev/null && echo "xmrig/crypto/cn/gpu/cn_gpu_avx.cpp" || echo)',
                '<!@(uname -m | grep "^x86_64$" >/dev/null && echo "xmrig/crypto/cn/gpu/cn_gpu_ssse3.cpp" || echo)',
                '<!@(uname -m | grep "^x86_64$" >/dev/null || echo "xmrig/crypto/cn/gpu/cn_gpu_arm.cpp" || echo)',
                '<!@(uname -m | grep "^x86_64$" >/dev/null && echo "xmrig-override/backend/cpu/platform/BasicCpuInfo.cpp" || echo)',
                '<!@(uname -m | grep "^x86_64$" >/dev/null || echo "xmrig-override/backend/cpu/platform/BasicCpuInfo_arm.cpp" || echo)',
                "multihashing.cc",
                "pearl_blake3.cc",
                "pearl_verify.cc",
                "xmrig-override/backend/cpu/Cpu.cpp",
                "c29b.cc",
                "c29i.cc",
                "c29s.cc",
                "c29v.cc",
		"c29.cc",
                "xmrig/crypto/cn/c_blake256.c",
                "xmrig/crypto/cn/c_groestl.c",
                "xmrig/crypto/cn/c_jh.c",
                "xmrig/crypto/cn/c_skein.c",
                "xmrig/base/crypto/keccak.cpp",
                "xmrig/base/crypto/sha3.cpp",
                "xmrig/crypto/cn/CnCtx.cpp",
                "xmrig/crypto/cn/CnHash.cpp",
                "xmrig/crypto/common/MemoryPool.cpp",
                "xmrig/crypto/common/VirtualMemory.cpp",
                "xmrig/crypto/common/VirtualMemory_unix.cpp",

                "xmrig/crypto/randomx/aes_hash.cpp",
                "xmrig/crypto/randomx/bytecode_machine.cpp",
                "xmrig/crypto/randomx/dataset.cpp",
                "xmrig/crypto/randomx/soft_aes.cpp",
                "xmrig/crypto/randomx/virtual_memory.cpp",
                "xmrig/crypto/randomx/vm_interpreted.cpp",
                "xmrig/crypto/randomx/allocator.cpp",
                "xmrig/crypto/randomx/randomx.cpp",
                "xmrig/crypto/randomx/superscalar.cpp",
                "xmrig/crypto/randomx/vm_compiled.cpp",
                "xmrig/crypto/randomx/vm_interpreted_light.cpp",
                "xmrig/crypto/randomx/blake2_generator.cpp",
                "xmrig/crypto/randomx/instructions_portable.cpp",
                "xmrig/crypto/randomx/reciprocal.c",
                "xmrig/crypto/randomx/virtual_machine.cpp",
                "xmrig/crypto/randomx/vm_compiled_light.cpp",
                "xmrig/crypto/randomx/blake2/blake2b.c",
                '<!@(uname -m | grep "^x86_64$" >/dev/null && echo "xmrig/crypto/randomx/blake2/blake2b_sse41.c" || echo)',
                '<!@(uname -m | grep "^x86_64$" >/dev/null && (./check_cpu.sh avx2 && echo "xmrig/crypto/randomx/blake2/avx2/blake2b_avx2.c" || echo "xmrig/crypto/randomx/blake2/avx2/blake2b_avx2_stub.c") || echo)',
                '<!@(uname -m | grep "^x86_64$" >/dev/null && echo "xmrig/crypto/randomx/jit_compiler_x86_static.S" || echo)',
                '<!@(uname -m | grep "^x86_64$" >/dev/null && echo "xmrig/crypto/randomx/jit_compiler_x86.cpp" || echo)',
                '<!@(uname -m | grep -E "^(arm64|aarch64)$" >/dev/null && echo "xmrig/crypto/randomx/jit_compiler_a64_static.S" || echo)',
                '<!@(uname -m | grep -E "^(arm64|aarch64)$" >/dev/null && echo "xmrig/crypto/randomx/jit_compiler_a64.cpp" || echo)',

                "xmrig/3rdparty/argon2/lib/argon2.c",
                "xmrig/3rdparty/argon2/lib/core.c",
                "xmrig/3rdparty/argon2/lib/encoding.c",
                "xmrig/3rdparty/argon2/lib/genkat.c",
                "xmrig/3rdparty/argon2/lib/impl-select.c",
                "xmrig/3rdparty/argon2/lib/blake2/blake2.c",
                '<!@(uname -m | grep "^x86_64$" >/dev/null && echo "xmrig/3rdparty/argon2/arch/x86_64/lib/argon2-arch.c" || echo)',
                '<!@(uname -m | grep "^x86_64$" >/dev/null && echo "xmrig/3rdparty/argon2/arch/x86_64/lib/argon2-avx2.c" || echo)',
                '<!@(uname -m | grep "^x86_64$" >/dev/null && echo "xmrig/3rdparty/argon2/arch/x86_64/lib/argon2-avx512f.c" || echo)',
                '<!@(uname -m | grep "^x86_64$" >/dev/null && echo "xmrig/3rdparty/argon2/arch/x86_64/lib/argon2-sse2.c" || echo)',
                '<!@(uname -m | grep "^x86_64$" >/dev/null && echo "xmrig/3rdparty/argon2/arch/x86_64/lib/argon2-ssse3.c" || echo)',
                '<!@(uname -m | grep "^x86_64$" >/dev/null && echo "xmrig/3rdparty/argon2/arch/x86_64/lib/argon2-xop.c" || echo)',
                '<!@(uname -m | grep "^x86_64$" >/dev/null || echo "xmrig/3rdparty/argon2/arch/generic/lib/argon2-arch.c" || echo)',

                "xmrig/crypto/astrobwt/AstroBWT.cpp",
                "xmrig/crypto/astrobwt/Salsa20.cpp",
                "xmrig/crypto/astrobwt/sort_indices2.cpp",
                "xmrig/crypto/astrobwt/salsa20_ref/salsa20.c",

                "xmrig/crypto/randomx/panthera/KangarooTwelve.c",
                "xmrig/crypto/randomx/panthera/KeccakP-1600-reference.c",
                "xmrig/crypto/randomx/panthera/KeccakSpongeWidth1600.c",
                "xmrig/crypto/randomx/panthera/sha256.c",
                "xmrig/crypto/randomx/panthera/yespower-opt.c",

                "xmrig/crypto/ghostrider/sph_blake.c",
                "xmrig/crypto/ghostrider/sph_bmw.c",
                "xmrig/crypto/ghostrider/sph_cubehash.c",
                "xmrig/crypto/ghostrider/sph_echo.c",
                "xmrig/crypto/ghostrider/sph_fugue.c",
                "xmrig/crypto/ghostrider/sph_groestl.c",
                "xmrig/crypto/ghostrider/sph_hamsi.c",
                "xmrig/crypto/ghostrider/sph_hamsi_helper.c",
                "xmrig/crypto/ghostrider/sph_jh.c",
                "xmrig/crypto/ghostrider/sph_keccak.c",
                "xmrig/crypto/ghostrider/sph_luffa.c",
                "xmrig/crypto/ghostrider/sph_sha2.c",
                "xmrig/crypto/ghostrider/sph_shabal.c",
                "xmrig/crypto/ghostrider/sph_shavite.c",
                "xmrig/crypto/ghostrider/sph_simd.c",
                "xmrig/crypto/ghostrider/sph_skein.c",
                "xmrig/crypto/ghostrider/sph_whirlpool.c",
                "xmrig-override/crypto/ghostrider/ghostrider.cpp",

                "xmrig-override/crypto/kawpow/KPHash.cpp",
                "xmrig/crypto/kawpow/KPHash.cpp",
                "xmrig/crypto/kawpow/KPCache.cpp",
                "xmrig/3rdparty/libethash/keccakf800.c",
                "xmrig/3rdparty/libethash/ethash_internal.c",
            ],
            "include_dirs": [
                "xmrig-override",
                "xmrig",
                "xmrig/3rdparty/argon2/include",
                "xmrig/3rdparty/argon2/lib",
                "<!(node -e \"require('nan')\")"
            ],
            "cflags_c": [
                '<!@(./check_cpu.sh intel && echo -DCPU_INTEL || (./check_cpu.sh amd && (./check_cpu.sh amdnew && echo -DCPU_AMD || echo -DCPU_AMD_OLD) || echo))',
                '<!@(./check_cpu.sh avx2 && echo -DHAVE_AVX2 || echo)',
                '<!@(./check_cpu.sh sse2 && echo -DHAVE_SSE2 || echo)',
                '<!@(./check_cpu.sh ssse3 && echo -DHAVE_SSSE3 || echo)',
                '<!@(./check_cpu.sh avx512f && echo -DHAVE_AVX512F || echo)',
                '<!@(./check_cpu.sh xop && echo -DHAVE_XOP || echo)',
                "-std=gnu11      -fPIC -DNDEBUG -Ofast -fno-fast-math -w"
            ],
            "asflags": [
                "-fPIC"
            ],
            "cflags_cc": [
                '<!@(./check_cpu.sh intel && echo -DCPU_INTEL || (./check_cpu.sh amd && (./check_cpu.sh amdnew && echo -DCPU_AMD || echo -DCPU_AMD_OLD) || echo))',
                "-std=gnu++20 -s -fPIC -DNDEBUG -Ofast -fno-fast-math -fexceptions -fno-rtti -Wno-class-memaccess -w"
            ],
            'cflags!': [ '-fexceptions' ]
        }
    ]
}
