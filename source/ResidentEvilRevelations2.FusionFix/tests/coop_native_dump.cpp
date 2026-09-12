// Standalone, offline harness. No Windows API or game process access.
#include "../CoopNativeCode.h"
#include "../CoopMenuNativeCode.h"
#include <iostream>
#include <iomanip>

void print(const std::string& name, const rev2coop::Bytes& code)
{
    std::cout << name << ' ' << std::hex << std::setfill('0');
    for (auto b : code) std::cout << std::setw(2) << unsigned(b);
    std::cout << '\n';
}
int main()
{
    using namespace rev2coop;
    for (size_t i = 0; i < InputGates.size(); ++i)
        print("input" + std::to_string(i), InputCode(0x2000000, 0x2002000, InputGates[i]));
    print("interactionCandidate", InteractionCandidateCode(0x2000000));
    print("interactionCandidateAlt", InteractionCandidateAltCode(0x2000000));
    for (size_t i = 0; i < PromptInputGates.size(); ++i)
        print("promptInput" + std::to_string(i),
            PromptInputCode(0x2000000, PromptInputGates[i]));
    for (size_t i = 0; i < TutorialPromptSites.size(); ++i)
        print("tutorialPrompt" + std::to_string(i),
            TutorialPromptCode(0x2000000, TutorialPromptSites[i]));
    for (size_t i = 0; i < 6; ++i)
    {
        constexpr std::array<std::array<uint32_t, 6>, 6> cases = {{
            {FileTextVtable, FileTextActiveMask, 1, 1, 3840, 1080},
            {FileTextVtable, FileTextActiveMask, 1, 0, 3840, 1080},
            {FileTextVtable, FileTextActiveMask, 0, 1, 3840, 1080},
            {FileTextVtable + 4, FileTextActiveMask, 1, 1, 3840, 1080},
            {FileTextVtable, 0, 1, 1, 3840, 1080},
            {FileTextVtable, FileTextActiveMask, 1, 1, 3441, 1440},
        }};
        Code c;
        c.word(ShouldReplayFileText(cases[i][0], cases[i][1],
            cases[i][2] != 0, cases[i][3] != 0, cases[i][4], cases[i][5]) ? 1 : 0);
        print("fileTextReplay" + std::to_string(i), c.bytes);
    }
    {
        const FileTextReplayPosition position{37.5f, 3840};
        auto value = position.ReplayX();
        uint32_t bits = 0;
        std::memcpy(&bits, &value, sizeof(bits));
        Code shifted; shifted.word(bits); print("fileTextShift", shifted.bytes);
        position.Restore(value);
        std::memcpy(&bits, &value, sizeof(bits));
        Code restored; restored.word(bits); print("fileTextRestore", restored.bytes);
    }
    print("geometry", GeometryCode(0x2000000, 0x2002000));
    print("capture", CaptureCode(0x2000000, 0x2002000));
    constexpr uint32_t menu = 0x2100000;
    constexpr uint32_t config = menu + 0x5000;
    print("inventorySafe", ConfirmedInventoryCode());
    print("inventoryBound", BindInventoryConfig(ConfirmedInventoryCode(), config));
    print("inventoryConfig", InventoryConfig(0x12345678));
    print("inventoryDraw", InventoryDrawWrapper(menu + 0x1000,
        menu + InventoryDrawOffset, config));
    print("inventoryStandard", InventoryPreviewWrapper(menu + 0x1800,
        menu + InventorySizeStandardOffset, config, false));
    print("inventoryAlternate", InventoryPreviewWrapper(menu + 0x2000,
        menu + InventorySizeAlternateOffset, config, true));
    print("shortcutUpdate", ShortcutUpdateWrapper(config));
    print("commandFar", CommandFarAnimationCode(0x2201000));
    size_t nearTest = 0;
    for (const auto test : {
        std::array<float, 7>{480, 540, 0, 0, 960, 1080, 40},
        std::array<float, 7>{40, 540, 0, 0, 960, 1080, 40},
        std::array<float, 7>{920, 540, 0, 0, 960, 1080, 40},
        std::array<float, 7>{480, 40, 0, 0, 960, 1080, 40},
        std::array<float, 7>{480, 1040, 0, 0, 960, 1080, 40}})
    {
        Code c; c.word(PartnerNearInside(test[0], test[1], test[2], test[3],
            test[4], test[5], test[6]) ? 1 : 0);
        print("nearInside" + std::to_string(nearTest++), c.bytes);
    }
    for (uint32_t flags : {0xFF150002u, 0xFF120002u, 0xFF130002u, 0xFF100002u})
        for (bool coop : {false, true})
        {
            Code c; c.word(SelectHudFlags(flags, coop));
            print("flags" + std::to_string(flags) + (coop ? "mp" : "sp"), c.bytes);
        }
}
