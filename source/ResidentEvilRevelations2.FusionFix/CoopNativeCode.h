#pragma once

// Build-pinned x86 code shared by the ASI and the offline CPU tests. No Windows
// or process access here. Input thunks deliberately match the confirmed live
// experiment byte-for-byte; only HUD node discovery becomes instance-independent.
#include <array>
#include <cstdint>
#include <cstring>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace rev2coop
{
using Bytes = std::vector<uint8_t>;
constexpr uint32_t ModePointer = 0x157AE00;
constexpr uint32_t ActorManager = 0x1567EAC;
constexpr uint32_t GeometrySite = 0xE6308A;
constexpr uint32_t InputSite = 0x98861C;
constexpr uint32_t ViewportGfxPointer = 0x15DE88C;
constexpr uint32_t InteractionCandidateSite = 0x701955;
constexpr uint32_t InteractionCandidateReturn = 0x70195B;
constexpr uint32_t InteractionCandidateSkip = 0x701972;
constexpr uint32_t InteractionCandidateAltSite = 0x701886;
constexpr uint32_t InteractionCandidateAltReturn = 0x70188D;
constexpr uint32_t InteractionCandidateAltSkip = 0x70189E;
constexpr uint32_t ActionIconVtable = 0x013915B0;
constexpr uint32_t ActionIcon2Vtable = 0x01391970;
constexpr uint32_t TutorialVtable = 0x013BEDE0;
constexpr uint32_t TutorialParserEntry = 0x009523D0;
constexpr uint32_t TutorialParserControllerStackOffset = 0xFC;

struct HudClass
{
    uint32_t vtable, update, layoutCall, layoutTest;
    std::array<uint32_t, 2> nodes;
    size_t count;
};
inline constexpr std::array<HudClass, 5> HudClasses = {{
    {0x139AE20, 0x8E4020, 0x8E4062, 0x8E4067, {0, 4}, 2},
    {0x139B998, 0x8E9980, 0x8E99CC, 0x8E99D1, {3, 4}, 2},
    {0x139BAF0, 0x8E9E70, 0x8E9E9E, 0x8E9EA3, {0, 0}, 1},
    {0x139B558, 0x8E8360, 0x8E8389, 0x8E838E, {2, 0}, 1},
    {0x13A3868, 0x94FC00, 0x94FC34, 0x94FC3C, {0, 0}, 1},
}};

// MOV ESI,<actor register> encoding, followed by original CMP operand.
struct InputGate { uint32_t site; uint8_t actorMov, cmpModRM; bool actorPredicate = false; };
inline constexpr std::array<InputGate, 29> InputGates = {{
    {0x7017D5, 0xF3, 0xB8}, {0x704635, 0xF6, 0xB9},
    {0xA126EF, 0xF7, 0xB9}, {0xA127F2, 0xF7, 0xB8},
    {0xA128D2, 0xF7, 0xB9}, {0xA12AA4, 0xF7, 0xB9},
    {0xA14E29, 0xF1, 0xB8}, {0xA14ECA, 0xF0, 0xB8, true},
    {0xA154E4, 0xF6, 0xB8}, {0xA155A5, 0xF6, 0xB8},
    {0xA15BD3, 0xF6, 0xB8}, {0xA15CC4, 0xF6, 0xB8},
    {0xA15D09, 0xF6, 0xB8}, {0xA1688F, 0xF6, 0xB8},
    {0xA16BC3, 0xF6, 0xB8}, {0xA171F8, 0xF3, 0xB8},
    {0xA17371, 0xF3, 0xB8}, {0xA17460, 0xF7, 0xB8},
    {0xA1751F, 0xF6, 0xB8}, {0xA17716, 0xF3, 0xB8},
    {0xA17831, 0xF3, 0xB8}, {0xA17CC9, 0xF6, 0xB8},
    {0xA17E8A, 0xF7, 0xB8}, {0xA17FB4, 0xF7, 0xB8},
    {0xA18086, 0xF7, 0xB8}, {0xA1824D, 0xF7, 0xB8},
    {0xA1838F, 0xF3, 0xB8}, {0xA186E6, 0xF7, 0xB8},
    // Interactable-object dispatcher. EBP is the actor selected from the
    // native player index immediately before this global input-mode branch.
    {0x40EF84, 0xF5, 0xB8},
}};

struct PromptInputGate
{
    uint32_t site;
    uint8_t objectMov;
    std::array<uint32_t, 2> vtables;
    size_t count;
};

inline constexpr std::array<PromptInputGate, 5> PromptInputGates = {{
    {0x0088DFBF, 0xF6, {ActionIconVtable, 0}, 1},
    {0x0088E0F9, 0xF1, {ActionIconVtable, ActionIcon2Vtable}, 2},
    {0x0088F57E, 0xF6, {ActionIcon2Vtable, 0}, 1},
    {0x0088FF01, 0xF6, {ActionIcon2Vtable, 0}, 1},
    {0x0088FFAF, 0xF6, {ActionIcon2Vtable, 0}, 1},
}};

inline constexpr std::array<uint32_t, 2> TutorialPromptSites = {{
    0x009525F7, 0x0095265B,
}};

inline constexpr uint32_t FileTextVtable = 0x013999A8;
inline constexpr uint32_t FileTextActiveMask = 0x200;

inline bool ShouldReplayFileText(uint32_t vtable, uint32_t stateFlags,
    bool dualMonitor, bool splitScreen, uint32_t physicalWidth,
    uint32_t physicalHeight)
{
    return dualMonitor && splitScreen && vtable == FileTextVtable &&
        (stateFlags & FileTextActiveMask) != 0 && physicalWidth >= 2 &&
        (physicalWidth & 1) == 0 && physicalHeight != 0;
}

inline float FileTextReplayX(float originalX, uint32_t physicalWidth)
{
    return originalX + static_cast<float>(physicalWidth) * 0.5f;
}

struct FileTextReplayPosition
{
    float originalX;
    uint32_t physicalWidth;
    float ReplayX() const { return FileTextReplayX(originalX, physicalWidth); }
    void Restore(float& target) const { target = originalX; }
};

inline Bytes Hex(const char* text)
{
    Bytes bytes;
    while (*text)
    {
        if (*text == ' ') { ++text; continue; }
        auto digit = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
        bytes.push_back(static_cast<uint8_t>((digit(text[0]) << 4) | digit(text[1])));
        text += 2;
    }
    return bytes;
}

struct Code
{
    Bytes bytes;
    std::map<std::string, size_t> labels;
    std::vector<std::pair<size_t, std::string>> fixups;
    void emit(const char* text) { auto b = Hex(text); bytes.insert(bytes.end(), b.begin(), b.end()); }
    void word(uint32_t v) { for (int i = 0; i < 4; ++i) bytes.push_back(uint8_t(v >> (8 * i))); }
    void label(const std::string& name) { labels.emplace(name, bytes.size()); }
    void branch(const char* op, const std::string& name)
    { emit(op); fixups.emplace_back(bytes.size(), name); word(0); }
    void jumpTo(uint32_t address, uint32_t target)
    { emit("e9"); word(target - address - static_cast<uint32_t>(bytes.size()) - 4); }
    Bytes finish(size_t limit)
    {
        for (const auto& f : fixups)
        {
            const auto delta = uint32_t(labels.at(f.second) - f.first - 4);
            std::memcpy(bytes.data() + f.first, &delta, 4);
        }
        if (bytes.size() > limit) throw std::runtime_error("RE:Rev2 native thunk exceeds slot");
        return bytes;
    }
};

inline Bytes Original(const InputGate& gate)
{
    Code c;
    c.bytes = {0x83, gate.cmpModRM};
    c.word(gate.actorPredicate ? 0x7920 : 0x15C4BC);
    c.bytes.push_back(gate.actorPredicate ? 0 : 1);
    return c.bytes;
}

inline Bytes InputCode(uint32_t address, uint32_t counter, const InputGate& gate)
{
    Code c;
    c.bytes = Original(gate);
    c.emit("9c 60");
    c.branch("0f 85", "native");
    c.bytes.insert(c.bytes.end(), {0x8B, gate.actorMov});
    c.emit("a1"); c.word(ModePointer);
    c.emit("85 c0"); c.branch("0f 84", "native");
    c.emit("83 b8 f0 08 00 00 01"); c.branch("0f 85", "native");
    c.emit("85 f6"); c.branch("0f 84", "blocked");
    c.emit("8b 90 f8 08 00 00 83 fa 08"); c.branch("0f 83", "blocked");
    c.emit("8b 0d"); c.word(ActorManager);
    c.emit("85 c9"); c.branch("0f 84", "blocked");
    c.emit("3b 74 91 20"); c.branch("0f 85", "blocked");
    c.emit("f0 ff 05"); c.word(counter); c.branch("e9", "done");
    c.label("blocked");
    c.emit("f0 ff 05"); c.word(counter + 4);
    c.emit("83 64 24 20 bf"); c.branch("e9", "done");
    c.label("native");
    c.emit("f0 ff 05"); c.word(counter + 8);
    c.label("done");
    c.emit("61 9d"); c.jumpTo(address, gate.site + 7);
    return c.finish(0x100);
}

inline Bytes InteractionCandidateOriginal()
{
    // mov eax,[esi+0x2d0] -- candidate state loaded before the native
    // status-specific early-return tests in the P1 keyboard path.
    return Hex("8b 86 d0 02 00 00");
}

inline Bytes InteractionCandidateCode(uint32_t address)
{
    Code c;
    c.bytes = InteractionCandidateOriginal();
    c.emit("9c 60");
    c.emit("a1"); c.word(ModePointer);
    c.emit("85 c0"); c.branch("0f 84", "native");
    c.emit("83 b8 f0 08 00 00 01"); c.branch("0f 85", "native");
    c.emit("83 b8 f4 08 00 00 01"); c.branch("0f 85", "native");
    c.emit("8b 90 f8 08 00 00 83 fa 08"); c.branch("0f 83", "native");
    c.emit("8b 0d"); c.word(ActorManager);
    c.emit("85 c9"); c.branch("0f 84", "native");
    c.emit("3b 5c 91 20"); c.branch("0f 85", "native");
    c.emit("8b 90 fc 08 00 00");
    c.emit("3b 96 ac 02 00 00"); c.branch("0f 85", "native");

    // P1 must not inherit a shared candidate owned by assigned P2. Skip it
    // before status 3..5/10 can reject P1's actor-local LMB action.
    c.emit("61 9d"); c.jumpTo(address, InteractionCandidateSkip);
    c.label("native");
    c.emit("61 9d"); c.jumpTo(address, InteractionCandidateReturn);
    return c.finish(0x100);
}

inline Bytes InteractionCandidateAltOriginal()
{
    // cmp dword ptr [edi+0x2d0],1 -- the earlier F/X interaction candidate
    // group uses EDI rather than the E/A group's ESI state load.
    return Hex("83 bf d0 02 00 00 01");
}

inline Bytes InteractionCandidateAltCode(uint32_t address)
{
    Code c;
    c.bytes = InteractionCandidateAltOriginal();
    c.emit("9c 60");
    c.emit("a1"); c.word(ModePointer);
    c.emit("85 c0"); c.branch("0f 84", "native_saved");
    c.emit("83 b8 f0 08 00 00 01"); c.branch("0f 85", "native_saved");
    c.emit("83 b8 f4 08 00 00 01"); c.branch("0f 85", "native_saved");
    c.emit("8b 90 f8 08 00 00 83 fa 08"); c.branch("0f 83", "native_saved");
    c.emit("8b 0d"); c.word(ActorManager);
    c.emit("85 c9"); c.branch("0f 84", "native_saved");
    c.emit("3b 5c 91 20"); c.branch("0f 85", "native_saved");
    c.emit("8b 90 fc 08 00 00");
    c.emit("3b 97 ac 02 00 00"); c.branch("0f 85", "native_saved");

    // P1 must not be rejected by the P2-owned F/X prompt candidate.
    c.emit("61 9d"); c.branch("e9", "skip_candidate");
    c.label("native_saved");
    c.emit("61 9d"); c.branch("e9", "native");
    c.label("native");
    c.jumpTo(address, InteractionCandidateAltReturn);
    c.label("skip_candidate");
    c.jumpTo(address, InteractionCandidateAltSkip);
    return c.finish(0x100);
}

inline Bytes PromptInputOriginal()
{
    return Hex("83 b8 bc c4 15 00 01");
}

inline Bytes PromptInputCode(uint32_t address, const PromptInputGate& gate)
{
    Code c;
    c.bytes = PromptInputOriginal();
    c.emit("9c 60");
    c.branch("0f 85", "native");
    c.bytes.insert(c.bytes.end(), {0x8B, gate.objectMov});
    c.emit("85 f6"); c.branch("0f 84", "native");
    c.emit("8b 0e");
    for (size_t i = 0; i < gate.count; ++i)
    {
        c.emit("81 f9"); c.word(gate.vtables[i]);
        if (i + 1 < gate.count)
            c.branch("0f 84", "class_ok");
        else
            c.branch("0f 85", "native");
    }
    c.label("class_ok");
    c.emit("a1"); c.word(ModePointer);
    c.emit("85 c0"); c.branch("0f 84", "native");
    c.emit("83 b8 f0 08 00 00 01"); c.branch("0f 85", "native");
    c.emit("83 b8 f4 08 00 00 01"); c.branch("0f 85", "native");
    c.emit("8b 90 fc 08 00 00 83 fa 08"); c.branch("0f 83", "native");
    c.emit("3b 96 ac 02 00 00"); c.branch("0f 85", "native");
    // Clear only ZF so the untouched native JNE selects its gamepad path.
    c.emit("83 64 24 20 bf");
    c.label("native");
    c.emit("61 9d"); c.jumpTo(address, gate.site + 7);
    return c.finish(0x100);
}

inline Bytes TutorialParserFrameOriginal()
{
    // This build-pinned prologue establishes the parser frame used by both
    // tutorial input gates. The async job's exact controller is at ESP+0xFC.
    return Hex("81 ec c4 00 00 00 53 55 8b ac 24 d0 00 00 00 56 8b f5 57 89 4c 24 18");
}

inline Bytes TutorialPromptCode(uint32_t address, uint32_t site)
{
    Code c;
    c.bytes = PromptInputOriginal();
    c.emit("9c 60");
    c.branch("0f 85", "native");
    // pushfd+pushad moved the current gate ESP by 0x24.
    c.emit("8b b4 24");
    c.word(TutorialParserControllerStackOffset + 0x24);
    c.emit("85 f6"); c.branch("0f 84", "native");
    c.emit("81 3e"); c.word(TutorialVtable); c.branch("0f 85", "native");
    c.emit("8b 8e ac 02 00 00 83 f9 08"); c.branch("0f 83", "native");
    c.emit("8b 15"); c.word(ModePointer);
    c.emit("85 d2"); c.branch("0f 84", "native");
    c.emit("83 ba f0 08 00 00 01"); c.branch("0f 85", "native");
    c.emit("83 ba f4 08 00 00 01"); c.branch("0f 85", "native");
    c.emit("8b 92 fc 08 00 00 83 fa 08"); c.branch("0f 83", "native");
    c.emit("3b ca"); c.branch("0f 85", "native");
    c.emit("83 64 24 20 bf");
    c.label("native");
    c.emit("61 9d"); c.jumpTo(address, site + 7);
    return c.finish(0x100);
}

inline Bytes GeometryCode(uint32_t address, uint32_t counter)
{
    Code c;
    c.emit("9c 52 83 f9 02"); c.branch("0f 85", "native");
    c.emit("8b 15"); c.word(ModePointer);
    c.emit("85 d2"); c.branch("0f 84", "native");
    c.emit("83 ba f0 08 00 00 01"); c.branch("0f 85", "native");
    c.emit("83 ba f4 08 00 00 01"); c.branch("0f 85", "native");
    // Live nodes owned by this controller only, not subclasses or cached heap
    // addresses. The node table is fetched afresh on every matrix recompute.
    c.emit("39 46 6c"); c.branch("0f 85", "native");
    for (size_t i = 0; i < HudClasses.size(); ++i)
    {
        auto next = "class" + std::to_string(i + 1);
        c.emit("81 38"); c.word(HudClasses[i].vtable); c.branch("0f 85", next);
        c.emit("8b 90 f8 00 00 00 85 d2"); c.branch("0f 84", "native");
        for (size_t j = 0; j < HudClasses[i].count; ++j)
        {
            c.emit("3b b2"); c.word(HudClasses[i].nodes[j] * 4);
            c.branch("0f 84", "uniform");
        }
        c.branch("e9", "native");
        c.label(next);
    }
    c.branch("e9", "native");
    c.label("uniform");
    c.emit("f0 ff 05"); c.word(counter);
    c.emit("f3 0f 10 8c c8 cc 01 00 00"); c.branch("e9", "done");
    c.label("native"); c.emit("f3 0f 10 8c c8 c8 01 00 00");
    c.label("done"); c.emit("5a 9d"); c.jumpTo(address, GeometrySite + 9);
    return c.finish(4096);
}

inline Bytes CaptureCode(uint32_t address, uint32_t capturedFlag)
{
    Code c;
    // Replace complete native JE. Auto-detection runs in SP AND MP, but the
    // ownership gates still reject P2. Captured bridge input follows pad-only.
    c.emit("9c 83 3d"); c.word(capturedFlag); c.emit("00");
    c.branch("0f 85", "pad");
    c.emit("9d"); c.jumpTo(address, 0x988622);
    c.label("pad"); c.emit("9d"); c.jumpTo(address, 0x9886A7);
    return c.finish(256);
}

inline uint32_t SelectHudFlags(uint32_t flags, bool coop)
{
    const uint32_t mode = (flags >> 16) & 15;
    if (mode != 2 && mode != 5) return flags;
    return (flags & ~0xF0000u) | (coop ? 0x20000u : 0x50000u);
}
}
