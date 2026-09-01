#pragma once
#include "CoopNativeCode.h"

// Included after the recovered renderer definitions in dllmain.cpp. These are
// the five accepted gameplay HUD classes, NOT a global SP canvas experiment.
namespace rev2coop
{
inline volatile LONG BridgeCaptured = 0;
inline bool InputInstalled = false;

template<class T> T& At(uintptr_t p) { return *reinterpret_cast<T*>(p); }
inline bool Active()
{
    const auto mode = At<uintptr_t>(ModePointer);
    return mode && At<uint32_t>(mode + 0x8F0) == 1 && At<uint32_t>(mode + 0x8F4) == 1;
}

template<size_t Index> uint32_t __fastcall UpdateHud(uintptr_t object, uintptr_t)
{
    constexpr auto def = HudClasses[Index];
    const auto result = reinterpret_cast<uint32_t(__thiscall*)(uintptr_t)>(def.update)(object);
    if (At<uint32_t>(object) != def.vtable) return result;
    const auto table = At<uintptr_t>(object + 0xF8);
    if (!table) return result;
    const bool coop = Active();
    for (size_t i = 0; i < def.count; ++i)
    {
        const auto node = At<uintptr_t>(table + 4 * def.nodes[i]);
        if (!node || At<uintptr_t>(node + 0x6C) != object) continue;
        auto& flags = At<uint32_t>(node + 0x80);
        const auto next = SelectHudFlags(flags, coop);
        if (flags != next)
        {
            flags = next;
            At<uint32_t>(node + 0x54) |= 0x10000; // invalidate native matrix cache
        }
    }
    return result;
}

inline void __fastcall DrawHud(int object, int unused, int context)
{
    if (Active()) sub_E18040(object, 0, context); // no legacy *.8 / +height*.25
    else sub_E18040_rescale(object, unused, context);
}

inline bool Matches(uintptr_t address, const Bytes& bytes)
{
    return !IsBadReadPtr(reinterpret_cast<void*>(address), bytes.size()) &&
        std::memcmp(reinterpret_cast<void*>(address), bytes.data(), bytes.size()) == 0;
}
inline bool MatchesWord(uintptr_t address, uint32_t value)
{
    Code c; c.word(value); return Matches(address, c.bytes);
}
inline void Put(uintptr_t address, Bytes bytes)
{
    injector::WriteMemoryRaw(address, bytes.data(), bytes.size(), true);
    FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(address), bytes.size());
}
inline Bytes Redirect(uint32_t site, uint32_t target, size_t size)
{
    Code c; c.jumpTo(site, target); c.bytes.resize(size, 0x90); return c.bytes;
}
inline uint32_t Allocate(size_t size)
{
    return reinterpret_cast<uint32_t>(VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
}
inline bool Seal(uint32_t address, size_t size)
{
    DWORD old;
    return VirtualProtect(reinterpret_cast<void*>(address), size, PAGE_EXECUTE_READ, &old) &&
        FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(address), size);
}
inline void Report(const char* message)
{
    OutputDebugStringA(message);
    DBGONLY(spd::log()->info("{}", message);)
}

inline bool InstallHud()
{
    const auto nativeGeometry = Hex("f3 0f 10 8c c8 c8 01 00 00");
    if (!Matches(GeometrySite, nativeGeometry)) return false;
    for (const auto& d : HudClasses)
    {
        Code call; call.emit("e8"); call.word(0x9553D0 - d.layoutCall - 5);
        if (!MatchesWord(d.vtable + 0x24, d.update) || !MatchesWord(d.vtable + 0x58, 0xE18040) ||
            !Matches(d.layoutCall, call.bytes) || !Matches(d.layoutTest, Hex("84 c0"))) return false;
    }
    if (!Matches(0x94FC39, Hex("51 8b ce"))) return false;
    const auto allocation = Allocate(8192);
    if (!allocation) return false;
    const auto code = GeometryCode(allocation, allocation + 4096);
    std::memcpy(reinterpret_cast<void*>(allocation), code.data(), code.size());
    if (!Seal(allocation, 4096)) { VirtualFree(reinterpret_cast<void*>(allocation), 0, MEM_RELEASE); return false; }
    // Install once during ASI initialization, before gameplay objects exist.
    // Executable/counter pages live until process exit, never freed in flight.
    const std::array<uintptr_t, 5> updates = {
        reinterpret_cast<uintptr_t>(&UpdateHud<0>), reinterpret_cast<uintptr_t>(&UpdateHud<1>),
        reinterpret_cast<uintptr_t>(&UpdateHud<2>), reinterpret_cast<uintptr_t>(&UpdateHud<3>),
        reinterpret_cast<uintptr_t>(&UpdateHud<4>)};
    Put(GeometrySite, Redirect(GeometrySite, allocation, 9));
    for (size_t i = 0; i < HudClasses.size(); ++i)
    {
        const auto& d = HudClasses[i];
        injector::WriteMemory<uint8_t>(d.layoutTest, 0x30, true); // layout-only TEST -> XOR
        injector::WriteMemory<uintptr_t>(d.vtable + 0x24, updates[i], true);
        injector::WriteMemory<uintptr_t>(d.vtable + 0x58, reinterpret_cast<uintptr_t>(&DrawHud), true);
    }
    return true;
}

inline bool InstallInput()
{
    // Guard native auto selector and actor lookup semantics as in live tests.
    if (!Matches(InputSite, Hex("0f 84 85 00 00 00")) ||
        !Matches(0x988610, Hex("a1 00 ae 57 01 83 b8 f0 08 00 00 01")) ||
        !Matches(0x988622, Hex("57 8b 3d 18 e9 5d 01 33 d2 eb 03")) ||
        !Matches(0x988680, Hex("c7 86 bc c4 15 00 01 00 00 00 89 86 c0 c4 15 00")) ||
        !Matches(0x9886A7, Hex("c7 86 bc c4 15 00 00 00 00 00 c7 86 c0 c4 15 00 00 00 00 00")) ||
        !Matches(0xA15521, Hex("83 be 20 79 00 00 00")) ||
        !Matches(0x6E6DC0, Hex("8b44240483f8ff7f0533c0c2040083f8087df68b448120c20400")) ||
        !Matches(0x886DD0, Hex("8b44240483f801770a8b8481f8080000c20400"))) return false;
    for (const auto& g : InputGates) if (!Matches(g.site, Original(g))) return false;
    const auto allocation = Allocate(0x3000);
    if (!allocation) return false;
    for (size_t i = 0; i < InputGates.size(); ++i)
    {
        const auto code = InputCode(allocation + uint32_t(i * 256), allocation + 0x2000 + uint32_t(i * 12), InputGates[i]);
        std::memcpy(reinterpret_cast<void*>(allocation + i * 256), code.data(), code.size());
    }
    const auto captureAddress = allocation + 0x1C00;
    const auto captureCode = CaptureCode(captureAddress, reinterpret_cast<uint32_t>(&BridgeCaptured));
    std::memcpy(reinterpret_cast<void*>(captureAddress), captureCode.data(), captureCode.size());
    if (!Seal(allocation, 0x2000)) { VirtualFree(reinterpret_cast<void*>(allocation), 0, MEM_RELEASE); return false; }
    for (size_t i = 0; i < InputGates.size(); ++i)
        Put(InputGates[i].site, Redirect(InputGates[i].site, allocation + uint32_t(i * 256), 7));
    // Enable native auto only AFTER every ownership gate has been installed.
    Put(InputSite, Redirect(InputSite, captureAddress, 6));
    InputInstalled = true;
    return true;
}

inline void PollBridgeCapture()
{
    if (!InputInstalled) return;
    static HWND bridge = nullptr;
    static ULONGLONG nextSearch = 0;
    auto isBridge = [](HWND window)
    {
        constexpr wchar_t prefix[] = L"RER2GamepadBridge-";
        wchar_t name[96] = {};
        DWORD pid = 0;
        if (!GetClassNameW(window, name, static_cast<int>(std::size(name))) ||
            wcsncmp(name, prefix, std::size(prefix) - 1) != 0) return false;
        wchar_t* end = nullptr;
        const auto namedPid = wcstoul(name + std::size(prefix) - 1, &end, 10);
        GetWindowThreadProcessId(window, &pid);
        return namedPid && end && !*end && pid == namedPid;
    };
    if (bridge && !isBridge(bridge)) bridge = nullptr;
    const auto now = GetTickCount64();
    if (!bridge && now >= nextSearch)
    {
        nextSearch = now + 500;
        HWND window = nullptr;
        while ((window = FindWindowExW(HWND_MESSAGE, window, nullptr, nullptr)) != nullptr)
        {
            if (isBridge(window)) { bridge = window; break; }
        }
    }
    DWORD_PTR response = 0;
    const bool ok = bridge && SendMessageTimeoutW(bridge, 0x8052, 1, 0,
        SMTO_ABORTIFHUNG | SMTO_BLOCK, 100, &response) && (response & 49) == 49;
    // IPC timeout/bridge exit -> release native input; no remote memory writer
    // or DLL dependency on Python. Never block the game's input/render thread.
    InterlockedExchange(&BridgeCaptured, ok && (response & 2) ? 1 : 0);
    if (!ok) bridge = nullptr;
}
}
