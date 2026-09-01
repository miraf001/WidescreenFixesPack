#pragma once
#include "CoopRuntime.h"
#include "CoopMenuNativeCode.h"
#include <cmath>

namespace rev2coop
{
inline Bytes RelativeCall(uint32_t site, uint32_t target)
{
    Code c;
    CallTo(c, site, target);
    return c.bytes;
}

inline uint32_t Pointer32(const void* pointer)
{
    return static_cast<uint32_t>(reinterpret_cast<uintptr_t>(pointer));
}

inline bool InstallInventory()
{
    if (!MatchesWord(InventoryDrawSlot, 0xE18040) ||
        !MatchesWord(InventoryUpdateSlot, InventoryUpdateEntry) ||
        !MatchesWord(ShortcutUpdateSlot, ShortcutUpdateEntry) ||
        !Matches(InventorySizeStandardCall,
            RelativeCall(InventorySizeStandardCall, InventoryNativeSize)) ||
        !Matches(InventorySizeAlternateCall,
            RelativeCall(InventorySizeAlternateCall, InventoryNativeSize))) return false;
    for (const auto site : InventoryLayoutTests)
        if (!Matches(site, Hex("84 c0"))) return false;

    constexpr size_t allocationSize = 0x6000;
    const auto allocation = Allocate(allocationSize);
    if (!allocation) return false;
    const auto configAddress = allocation + 0x5000;
    const auto drawAddress = allocation + 0x1000;
    const auto standardAddress = allocation + 0x1800;
    const auto alternateAddress = allocation + 0x2000;
    const auto shortcutAddress = allocation + 0x2800;
    try
    {
        const auto safe = BindInventoryConfig(ConfirmedInventoryCode(), configAddress);
        const auto draw = InventoryDrawWrapper(drawAddress,
            allocation + InventoryDrawOffset, configAddress);
        const auto standard = InventoryPreviewWrapper(standardAddress,
            allocation + InventorySizeStandardOffset, configAddress, false);
        const auto alternate = InventoryPreviewWrapper(alternateAddress,
            allocation + InventorySizeAlternateOffset, configAddress, true);
        const auto shortcut = ShortcutUpdateWrapper(configAddress);
        const auto config = InventoryConfig(Pointer32(reinterpret_cast<const void*>(&sub_E18040)));
        std::memcpy(reinterpret_cast<void*>(allocation), safe.data(), safe.size());
        std::memcpy(reinterpret_cast<void*>(drawAddress), draw.data(), draw.size());
        std::memcpy(reinterpret_cast<void*>(standardAddress), standard.data(), standard.size());
        std::memcpy(reinterpret_cast<void*>(alternateAddress), alternate.data(), alternate.size());
        std::memcpy(reinterpret_cast<void*>(shortcutAddress), shortcut.data(), shortcut.size());
        std::memcpy(reinterpret_cast<void*>(configAddress), config.data(), config.size());
    }
    catch (...)
    {
        VirtualFree(reinterpret_cast<void*>(allocation), 0, MEM_RELEASE);
        return false;
    }
    if (!Seal(allocation, 0x3000))
    {
        VirtualFree(reinterpret_cast<void*>(allocation), 0, MEM_RELEASE);
        return false;
    }

    // Publish only after every byte, vtable and callsite guard has passed.
    Put(InventorySizeStandardCall, RelativeCall(InventorySizeStandardCall, standardAddress));
    Put(InventorySizeAlternateCall, RelativeCall(InventorySizeAlternateCall, alternateAddress));
    injector::WriteMemory<uintptr_t>(InventoryDrawSlot, drawAddress, true);
    injector::WriteMemory<uintptr_t>(InventoryUpdateSlot,
        allocation + InventoryUpdateOffset, true);
    for (const auto site : InventoryLayoutTests)
        injector::WriteMemory<uint8_t>(site, 0x30, true); // local layout TEST -> XOR
    injector::WriteMemory<uintptr_t>(ShortcutUpdateSlot, shortcutAddress, true);
    return true;
}

inline bool KeyboardPartnerCommandEnabled = false;
inline ULONGLONG PartnerCommandExpiresAt = 0;
inline bool PartnerCommandNearOnscreen = true;
constexpr uint32_t PartnerCommandVisible = 0x4000;
constexpr ULONGLONG PartnerCommandLingerMs = 3000;

inline bool ValidPartnerController(uintptr_t object, uint32_t vtable)
{
    return object && !IsBadReadPtr(reinterpret_cast<void*>(object), 0x300) &&
        At<uint32_t>(object) == vtable && At<uint32_t>(object + 0x2AC) <= 1;
}

inline void LocalizePlayerTwoNear(uintptr_t object)
{
    const auto margin = At<float>(NativeSafeMargin);
    for (const auto fields : {std::array<uint32_t, 3>{0x40, 0x168, 0x170},
                              std::array<uint32_t, 3>{0x44, 0x16C, 0x174}})
    {
        const auto low = static_cast<float>(At<int32_t>(object + fields[1])) + margin;
        const auto high = static_cast<float>(At<int32_t>(object + fields[2])) - margin;
        if (!(high > low)) continue;
        auto& value = At<float>(object + fields[0]);
        value = std::clamp(value, low, high);
    }
}

inline bool PlayerOneNearIsOnscreen(uintptr_t object)
{
    const auto gfx = At<uintptr_t>(GfxPointer);
    if (!gfx || IsBadReadPtr(reinterpret_cast<void*>(gfx + 0x48), 16)) return false;
    const auto left = At<int32_t>(gfx + 0x48);
    const auto top = At<int32_t>(gfx + 0x4C);
    const auto right = At<int32_t>(gfx + 0x50);
    const auto bottom = At<int32_t>(gfx + 0x54);
    const auto margin = At<float>(NativeSafeMargin);
    const auto x = At<float>(object + 0x40);
    const auto y = At<float>(object + 0x44);
    return PartnerNearInside(x, y, static_cast<float>(left), static_cast<float>(top),
        static_cast<float>(right), static_cast<float>(bottom), margin);
}

inline uint32_t __fastcall UpdateCommandNear(uintptr_t object, uintptr_t)
{
    using NativeUpdate = uint32_t(__thiscall*)(uintptr_t);
    const auto native = reinterpret_cast<NativeUpdate>(NearUpdateEntry);
    if (!ValidPartnerController(object, NearVtable)) return native(object);
    const auto player = At<uint32_t>(object + 0x2AC);
    if (!Active())
    {
        At<uint8_t>(object + 0x2F8) = 0;
        if (player == 0)
        {
            PartnerCommandExpiresAt = 0;
            PartnerCommandNearOnscreen = true;
        }
        return native(object); // preserves native SP ChangeCharacter exactly
    }

    // P1 projection is physical==local and can use Capcom's native clamp.
    // P2 projection is already local, so it must be clamped after projection.
    At<uint8_t>(object + 0x2F8) = player == 0 ? 1 : 0;
    reinterpret_cast<NativeUpdate>(NearGenericUpdate)(object);

    bool tabProbe = false;
    if (player == 0 && KeyboardPartnerCommandEnabled)
    {
        const auto now = GetTickCount64();
        if ((GetAsyncKeyState(VK_TAB) & 0x8000) != 0)
            PartnerCommandExpiresAt = now + PartnerCommandLingerMs;
        tabProbe = now < PartnerCommandExpiresAt;
        if (tabProbe) At<uint32_t>(object + 0x0C) |= PartnerCommandVisible;
    }

    const auto result = reinterpret_cast<NativeUpdate>(NearProjection)(object);
    if (player == 1) LocalizePlayerTwoNear(object);
    if (tabProbe)
    {
        PartnerCommandNearOnscreen = PlayerOneNearIsOnscreen(object);
        if (!PartnerCommandNearOnscreen)
            At<uint32_t>(object + 0x0C) &= ~PartnerCommandVisible;
    }
    return result;
}

inline uint32_t __fastcall UpdateCommandFar(uintptr_t object, uintptr_t)
{
    using NativeUpdate = uint32_t(__thiscall*)(uintptr_t);
    const auto result = reinterpret_cast<NativeUpdate>(FarUpdateEntry)(object);
    if (!KeyboardPartnerCommandEnabled || !ValidPartnerController(object, FarVtable) ||
        At<uint32_t>(object + 0x2AC) != 0 || !Active()) return result;
    if (GetTickCount64() < PartnerCommandExpiresAt && !PartnerCommandNearOnscreen)
        At<uint32_t>(object + 0x0C) |= PartnerCommandVisible;
    return result;
}

inline bool InstallPartnerCommand(bool keyboardTab)
{
    Code farCall; CallTo(farCall, FarAnimationCall, FarAnimationUpdate);
    const float center800 = 800.0f;
    Bytes centerBytes(sizeof(center800));
    std::memcpy(centerBytes.data(), &center800, sizeof(center800));
    if (!Matches(FarAnimationCall, farCall.bytes) ||
        !Matches(FarCenterSite, centerBytes) ||
        !MatchesWord(FarDrawSlot,
            Pointer32(reinterpret_cast<const void*>(&sub_E18040_offset))) ||
        !MatchesWord(NearUpdateSlot, NearUpdateEntry) ||
        !MatchesWord(FarUpdateSlot, FarUpdateEntry)) return false;

    const auto allocation = Allocate(0x2000);
    if (!allocation) return false;
    Bytes code;
    try { code = CommandFarAnimationCode(allocation + 0x1000); }
    catch (...)
    {
        VirtualFree(reinterpret_cast<void*>(allocation), 0, MEM_RELEASE);
        return false;
    }
    std::memcpy(reinterpret_cast<void*>(allocation), code.data(), code.size());
    if (!Seal(allocation, 0x1000))
    {
        VirtualFree(reinterpret_cast<void*>(allocation), 0, MEM_RELEASE);
        return false;
    }

    const float center640 = 640.0f;
    injector::WriteMemory<float>(FarCenterSite, center640, true);
    Put(FarAnimationCall, RelativeCall(FarAnimationCall, allocation));
    injector::WriteMemory<uintptr_t>(FarDrawSlot,
        reinterpret_cast<uintptr_t>(&sub_E18040), true);
    injector::WriteMemory<uintptr_t>(NearUpdateSlot,
        reinterpret_cast<uintptr_t>(&UpdateCommandNear), true);
    injector::WriteMemory<uintptr_t>(FarUpdateSlot,
        reinterpret_cast<uintptr_t>(&UpdateCommandFar), true);
    KeyboardPartnerCommandEnabled = keyboardTab;
    return true;
}
}
