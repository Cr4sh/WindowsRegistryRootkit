
extern "C"
{
    void ClearWp(void);
    void SetWp(void);

    PVOID DoPointerFixup(PVOID Ptr, PUCHAR PointerFixup);
}

#define RECALCULATE_POINTER(_ptr_) DoPointerFixup((PVOID)(_ptr_), PointerFixup)
