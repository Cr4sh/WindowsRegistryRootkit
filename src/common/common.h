
#define TIME_ABSOLUTE(wait) (wait)
#define TIME_RELATIVE(wait) (-(wait))
#define TIME_NANOSECONDS(nanos) (((signed __int64)(nanos)) / 100L)
#define TIME_MICROSECONDS(micros) (((signed __int64)(micros)) * TIME_NANOSECONDS(1000L))
#define TIME_MILLISECONDS(milli) (((signed __int64)(milli)) * TIME_MICROSECONDS(1000L))
#define TIME_SECONDS(seconds) (((signed __int64)(seconds)) * TIME_MILLISECONDS(1000L))

#define RVATOVA(_base_, _offset_) ((PUCHAR)(_base_) + (ULONG)(_offset_))

#define MY_ALIGN_DOWN(_val_, _align_) ((_val_) &~ ((_align_) - 1))
#define MY_ALIGN_UP(_val_, _align_) (((_val_) & ((_align_) - 1)) ? MY_ALIGN_DOWN((_val_), (_align_)) + (_align_) : (_val_))

#define IFMT32 "0x%.8x"
#define IFMT64 "0x%.16I64x"


#define GET_NATIVE(_name_)                                      \
                                                                \
    func_##_name_ f_##_name_ = (func_##_name_)GetProcAddress(   \
        GetModuleHandle("ntdll.dll"),                           \
        (#_name_)                                               \
    );

#if defined(_X86_)

#define IFMT IFMT32

#elif defined(_AMD64_)

#define IFMT IFMT64

#endif
