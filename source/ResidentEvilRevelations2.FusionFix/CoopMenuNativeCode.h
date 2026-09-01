#pragma once

// Build-pinned, process-independent x86 used by the confirmed Campaign
// inventory/Quick Menu and uGUICommandFar fixes.  Keeping these builders free
// of Windows API calls lets the offline harness compare every emitted byte with
// the reversible live-test implementation before an ASI is deployed.
#include "CoopNativeCode.h"
#include <cmath>

namespace rev2coop
{
constexpr uint32_t InventoryDrawSlot = 0x139CD20;
constexpr uint32_t InventoryUpdateSlot = 0x139CCEC;
constexpr uint32_t InventoryUpdateEntry = 0x8F8970;
constexpr uint32_t InventorySizeStandardCall = 0x8F7A54;
constexpr uint32_t InventorySizeAlternateCall = 0x8FA310;
constexpr uint32_t InventoryNativeSize = 0x96C4D0;
constexpr uint32_t InventoryVtable = 0x139CCC8;
constexpr uint32_t InventoryItemDrawVtable = 0x13BF4D0;
constexpr uint32_t ShortcutVtable = 0x139AFB0;
constexpr uint32_t ShortcutUpdateSlot = ShortcutVtable + 0x24;
constexpr uint32_t ShortcutUpdateEntry = 0x8E53F0;
constexpr uint32_t GfxPointer = 0x15DE88C;
constexpr uint32_t InventoryConfigMarker = 0x0BADF00D;
constexpr size_t ShortcutNodeCount = 21;
inline constexpr std::array<uint32_t, 8> InventoryLayoutTests = {
    0x8F79E1, 0x8F7A01, 0x8F7A33, 0x8FA217,
    0x8FA25E, 0x8FA28F, 0x8FA2BD, 0x8FA2EF};

constexpr uint32_t InventoryDrawOffset = 0;
constexpr uint32_t InventoryUpdateOffset = 69;
constexpr uint32_t InventorySizeStandardOffset = 90;
constexpr uint32_t InventorySizeAlternateOffset = 117;

inline void CallTo(Code& c, uint32_t base, uint32_t target)
{
    const auto site = base + static_cast<uint32_t>(c.bytes.size());
    c.emit("e8");
    c.word(target - site - 5);
}

inline Bytes ConfirmedInventoryCode()
{
    // SHA-256 of the original COFF object: 9e2a6ff1553af2c3b2f18ab6b25c0d2
    // dc26553964d10fe0115207d7b4ef626a7.  This is safe -01, not the later
    // diagnostic InventoryPreviewLive.asm experiment.
    return Hex(
        "50a100ae570185c0743483b8f008000001752b83b8f408000001752258568b7424085633d2b80df0ad0bff501c9c50b80df0ad0bf0ff4020589d5ec2040058684080e100c3568bf1b870898f00ffd09c60e83c000000619d5ec3568bf1ff742408b8d0c49600ffd09c60e8a9010000619d5ec20400568bf1ff742408b8d0c49600ffd09c608bfbe88c010000619d5ec20400813ec8cc39010f8579010000a100ae570185c00f846c01000083b8f0080000010f855f01000083b8f4080000010f85520100008b86ac02000083f8010f87430100008b1d8ce85d0185db0f843501000069c0900100008d5c03488b43082b030f8e200100008b530c2b53040f8e140100008bbef800000085ff0f84060100008bbf0003000085ff0f84f8000000813f30d341010f85ec00000039776c0f85e3000000bd0df0ad0b81ec800000000f1104240f114c24100f115424200f115c24300f116424400f116c24500f117424600f117c2470f30f2ac2f30f5e4504f30f2ac8f30f5e4d08f30f5dc1f30f2acaf30f5e4d0cf30f5dc1f30f114528f30f2ac8f30f5e4d00f30f2ad2f30f5e5504f30f5dcaf30f5ec1f30f11452cf30f104d10f30f59c8f30f118fa0000000f30f104d14f30f59c8f30f118fa4000000f30f1187b0000000f30f1187b4000000814f5400000100f0ff45240f1004240f104c24100f105424200f105c24300f106424400f106c24500f107424600f107c247081c480000000c3813fc8cc39010f850b02000039b7cc0200000f85ff010000813ed0f43b010f85f301000080be90000000000f85e60100008b8e8c00000083f9010f87d7010000a100ae570185c00f84ca01000083b8f0080000010f85bd01000083b8f4080000010f85b00100008b1d8ce85d0185db0f84a201000069c9900100008d7c0b488b47082b070f8e8d0100008b570c2b57040f8e8101000083bbe0010000000f8e7401000083bbe4010000000f8e67010000bd0df0ad0b81ec800000000f1104240f114c24100f115424200f115c24300f116424400f116c24500f117424600f117c2470f30f2ac0f30f5e4500f30f2afaf30f5e7d04f30f5dc7f30f10cff30f2af0f30f5e7508f30f5dcef30f2af2f30f5e750cf30f5dce8b86ac0000002b86a40000000f8ec2000000f30f2ad08b86b00000002b86a80000000f8eac000000f30f2ad8f30f2ab3e0010000f30f597504f30f2aabe4010000f30f5ef5f30f5c7530f30f2cc6f30f2af08b86a40000002b07f30f2ae0f30f5ee0f30f5ce6f30f59e1f30f2a37f30f58e68b86a80000002b4704f30f2ae8f30f5ee8f30f59e9f30f2a7704f30f58eef30f5ed7f30f59d1f30f5edff30f59d9f30f58d4f30f58ddf30f2cc48986a4000000f30f2cc58986a8000000f30f2cc28986ac000000f30f2cc38986b0000000f0ff45180f1004240f104c24100f105424200f105c24300f106424400f106c24500f107424600f107c247081c480000000c3");
}

inline Bytes BindInventoryConfig(Bytes code, uint32_t config)
{
    size_t replacements = 0;
    for (size_t i = 0; i + 4 <= code.size(); ++i)
    {
        uint32_t value = 0;
        std::memcpy(&value, code.data() + i, 4);
        if (value != InventoryConfigMarker) continue;
        std::memcpy(code.data() + i, &config, 4);
        ++replacements;
        i += 3;
    }
    if (replacements != 4) throw std::runtime_error("Unexpected confirmed inventory marker count");
    return code;
}

inline Bytes InventoryConfig(uint32_t coreDraw)
{
    auto config = Hex(
        "0000a04400003444000075440080224400009c4200000a430000000000000000"
        "0000000000000000000000000000000000004844cdcccc3f0000c0be000080bf"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000803f0000003f0000000000000000000000000000aa4300005743");
    config.resize(4096);
    std::memcpy(config.data() + 0x1C, &coreDraw, sizeof(coreDraw));
    return config;
}

inline Bytes InventoryDrawWrapper(uint32_t address, uint32_t safeTarget, uint32_t config)
{
    Code c;
    c.emit("ff 74 24 04"); CallTo(c, address, safeTarget);
    c.emit("9c 60 83 ec 20 0f 11 04 24 0f 11 4c 24 10");
    c.emit("a1"); c.word(ModePointer); c.emit("85 c0"); c.branch("0f 84", "done");
    c.emit("83 b8 f0 08 00 00 01"); c.branch("0f 85", "done");
    c.emit("83 b8 f4 08 00 00 01"); c.branch("0f 85", "done");
    c.emit("8b 44 24 48 85 c0"); c.branch("0f 84", "done");
    c.emit("8b 40 04 85 c0"); c.branch("0f 84", "done");
    c.emit("8b b8 18 18 00 00 85 ff"); c.branch("0f 84", "done");
    c.emit("a1"); c.word(GfxPointer); c.emit("85 c0"); c.branch("0f 84", "done");
    c.emit("8b 50 50 2b 50 48 8b 48 54 2b 48 4c");
    c.emit("85 d2"); c.branch("0f 8e", "done"); c.emit("85 c9"); c.branch("0f 8e", "done");
    c.emit("f3 0f 2a c1 f3 0f 5e 05"); c.word(config + 0x04);
    c.emit("f3 0f 2a ca f3 0f 5e 0d"); c.word(config + 0x08);
    c.emit("f3 0f 5d c1 f3 0f 2a c9 f3 0f 5e 0d"); c.word(config + 0x0C);
    c.emit("f3 0f 5d c1 f3 0f 59 05"); c.word(config + 0x0C);
    c.emit("f3 0f 2a c9 f3 0f 5e c1 f3 0f 5c 05"); c.word(config + 0x60);
    c.emit("f3 0f 58 47 0c f3 0f 11 47 0c f0 ff 05"); c.word(config + 0x68);
    c.label("done");
    c.emit("0f 10 04 24 0f 10 4c 24 10 83 c4 20 61 9d c2 04 00");
    return c.finish(0x800);
}

inline Bytes InventoryPreviewWrapper(uint32_t address, uint32_t safeTarget,
    uint32_t config, bool ownerFromEbx)
{
    Code c;
    c.emit("51"); c.emit(ownerFromEbx ? "53" : "57");
    c.emit("ff 74 24 0c"); CallTo(c, address, safeTarget);
    c.emit("9c 60 83 ec 20 0f 11 04 24 0f 11 4c 24 10");
    c.emit("8b 7c 24 44 8b 74 24 48");
    c.emit("81 3f c8 cc 39 01"); c.branch("0f 85", "done");
    c.emit("39 b7 cc 02 00 00"); c.branch("0f 85", "done");
    c.emit("81 3e d0 f4 3b 01"); c.branch("0f 85", "done");
    c.emit("80 be 90 00 00 00 00"); c.branch("0f 85", "done");
    c.emit("8b 8e 8c 00 00 00 83 f9 01"); c.branch("0f 87", "done");
    c.emit("a1"); c.word(ModePointer); c.emit("85 c0"); c.branch("0f 84", "done");
    c.emit("83 b8 f0 08 00 00 01"); c.branch("0f 85", "done");
    c.emit("83 b8 f4 08 00 00 01"); c.branch("0f 85", "done");
    c.emit("a1"); c.word(GfxPointer); c.emit("85 c0"); c.branch("0f 84", "done");
    c.emit("69 c9 90 01 00 00 8d 7c 08 48");
    c.emit("8b 47 08 2b 07 8b 57 0c 2b 57 04");
    c.emit("85 c0"); c.branch("0f 8e", "done"); c.emit("85 d2"); c.branch("0f 8e", "done");
    c.emit("f3 0f 2a c2 f3 0f 5e 05"); c.word(config + 0x04);
    c.emit("f3 0f 2a c8 f3 0f 5e 0d"); c.word(config + 0x08);
    c.emit("f3 0f 5d c1 f3 0f 2a ca f3 0f 5e 0d"); c.word(config + 0x0C);
    c.emit("f3 0f 5d c1 f3 0f 59 05"); c.word(config + 0x0C);
    c.emit("f3 0f 2a ca f3 0f 5c c8 f3 0f 59 0d"); c.word(config + 0x64);
    c.emit("f3 0f 2c d1 01 96 a8 00 00 00 01 96 b0 00 00 00");
    c.emit("f0 ff 05"); c.word(config + 0x6C);
    c.label("done");
    c.emit("0f 10 04 24 0f 10 4c 24 10 83 c4 20 61 9d 83 c4 08 c2 04 00");
    return c.finish(0x800);
}

inline Bytes ShortcutUpdateWrapper(uint32_t config)
{
    Code c;
    c.emit("56 53 57 55 8b f1 b8"); c.word(ShortcutUpdateEntry); c.emit("ff d0 50 9c 60");
    c.emit("83 ec 40 0f 11 04 24 0f 11 4c 24 10 0f 11 54 24 20 0f 11 5c 24 30");
    c.emit("81 3e b0 af 39 01"); c.branch("0f 85", "done");
    c.emit("a1"); c.word(ModePointer); c.emit("85 c0"); c.branch("0f 84", "done");
    c.emit("83 b8 f0 08 00 00 01"); c.branch("0f 85", "done");
    c.emit("83 b8 f4 08 00 00 01"); c.branch("0f 85", "done");
    c.emit("8b 86 ac 02 00 00 83 f8 01"); c.branch("0f 87", "done");
    c.emit("8b 2d"); c.word(GfxPointer); c.emit("85 ed"); c.branch("0f 84", "done");
    c.emit("69 c0 90 01 00 00 8d 6c 05 48");
    c.emit("8b 55 08 2b 55 00 8b 4d 0c 2b 4d 04");
    c.emit("85 d2"); c.branch("0f 8e", "done"); c.emit("85 c9"); c.branch("0f 8e", "done");
    c.emit("8b ae f8 00 00 00 85 ed"); c.branch("0f 84", "done");
    c.emit("8b 6d 00 85 ed"); c.branch("0f 84", "done");
    c.emit("81 7d 00 30 d3 41 01"); c.branch("0f 85", "done");
    c.emit("39 75 6c"); c.branch("0f 85", "done");
    c.emit("81 bd a0 00 00 00 00 00 aa 43"); c.branch("0f 85", "done");
    c.emit("81 bd a4 00 00 00 00 00 8c 43"); c.branch("0f 85", "done");
    c.emit("81 bd b0 00 00 00 00 00 80 3f"); c.branch("0f 85", "done");
    c.emit("81 bd b4 00 00 00 00 00 80 3f"); c.branch("0f 85", "done");
    c.emit("f3 0f 2a c1 f3 0f 5e 05"); c.word(config + 0x04);
    c.emit("f3 0f 2a da f3 0f 5e 1d"); c.word(config + 0x08);
    c.emit("f3 0f 5d c3 f3 0f 2a d9 f3 0f 5e 1d"); c.word(config + 0x0C);
    c.emit("f3 0f 5d c3");
    c.emit("f3 0f 2a ca f3 0f 5e 0d"); c.word(config + 0x00);
    c.emit("f3 0f 2a d9 f3 0f 5e 1d"); c.word(config + 0x04);
    c.emit("f3 0f 5d cb 0f 28 d0 f3 0f 5e d1");
    c.emit("f3 0f 10 1d"); c.word(config + 0x74);
    c.emit("f3 0f 59 da f3 0f 11 9d a0 00 00 00");
    c.emit("f3 0f 11 95 b0 00 00 00 f3 0f 11 95 b4 00 00 00");
    c.emit("f3 0f 10 1d"); c.word(config + 0x78);
    c.emit("f3 0f 59 da f3 0f 11 9d a4 00 00 00");
    c.emit("f3 0f 10 1d"); c.word(config + 0x78);
    c.emit("f3 0f 59 d8 f3 0f 5c 5d 44");
    c.emit("8b be f8 00 00 00 85 ff"); c.branch("0f 84", "matrix_done");
    c.emit("b9"); c.word(static_cast<uint32_t>(ShortcutNodeCount));
    c.label("matrix_loop");
    c.emit("8b 07 83 c7 04 85 c0"); c.branch("0f 84", "matrix_next");
    c.emit("39 70 6c"); c.branch("0f 85", "matrix_next");
    c.emit("8b 50 40 0b 50 44"); c.branch("0f 84", "matrix_next");
    c.emit("83 78 24 00"); c.branch("0f 84", "matrix_next");
    c.emit("f3 0f 10 50 44 f3 0f 58 d3 f3 0f 11 50 44");
    c.label("matrix_next"); c.emit("49"); c.branch("0f 85", "matrix_loop");
    c.label("matrix_done");
    c.emit("81 4d 54 00 00 01 00 f0 ff 05"); c.word(config + 0x70);
    c.label("done");
    c.emit("0f 10 04 24 0f 10 4c 24 10 0f 10 54 24 20 0f 10 5c 24 30");
    c.emit("83 c4 40 61 9d 58 5d 5f 5b 5e c3");
    return c.finish(0x800);
}

constexpr uint32_t FarVtable = 0x139AB40;
constexpr uint32_t FarUpdateSlot = FarVtable + 0x24;
constexpr uint32_t FarUpdateEntry = 0x8E29E0;
constexpr uint32_t FarDrawSlot = FarVtable + 0x58;
constexpr uint32_t FarCenterSite = 0x8E2A13;
constexpr uint32_t FarAnimationCall = 0x8E323F;
constexpr uint32_t FarAnimationUpdate = 0xE68DF0;
constexpr uint32_t NearVtable = 0x139ACA0;
constexpr uint32_t NearUpdateSlot = NearVtable + 0x24;
constexpr uint32_t NearUpdateEntry = 0x8E34F0;
constexpr uint32_t NearGenericUpdate = 0x9690F0;
constexpr uint32_t NearProjection = 0x8E36A0;
constexpr uint32_t NativeSafeMargin = 0x14DD080;

inline Bytes CommandFarAnimationCode(uint32_t counter)
{
    Code c;
    c.emit("56 8b f1 ff 74 24 0c ff 74 24 0c b8"); c.word(FarAnimationUpdate);
    c.emit("ff d0 50 8b 46 6c 85 c0"); c.branch("0f 84", "done");
    c.emit("81 38"); c.word(FarVtable); c.branch("0f 85", "done");
    c.emit("8b 15"); c.word(ModePointer); c.emit("85 d2"); c.branch("0f 84", "done");
    c.emit("83 ba f0 08 00 00 01"); c.branch("0f 85", "done");
    c.emit("83 ba f4 08 00 00 01"); c.branch("0f 85", "done");
    c.emit("83 b8 ac 02 00 00 01"); c.branch("0f 87", "done");
    c.emit("8b 8e e8 00 00 00 85 c9"); c.branch("0f 84", "done");
    c.emit("f3 0f 2a 80 68 01 00 00 f3 0f 58 05"); c.word(NativeSafeMargin);
    c.emit("f3 0f 2a 88 70 01 00 00 f3 0f 5c 0d"); c.word(NativeSafeMargin);
    c.emit("0f 2f c8"); c.branch("0f 86", "done");
    c.emit("8b 11 85 d2"); c.branch("0f 84", "done");
    c.emit("f3 0f 10 62 10 0f 57 ed 0f 2f e5"); c.branch("0f 86", "done");
    c.emit("f3 0f 10 5a 40 8b 51 04 85 d2"); c.branch("0f 84", "done");
    c.emit("f3 0f 10 92 80 00 00 00");
    c.emit("f3 0f 59 d4 f3 0f 58 d3 f3 0f 5f d0 f3 0f 5d d1");
    c.emit("f3 0f 10 ea f3 0f 5c eb f3 0f 5e ec");
    c.emit("f3 0f 11 aa 80 00 00 00");
    for (size_t i = 0; i < 6; ++i)
    {
        const auto next = "child" + std::to_string(i + 1);
        c.emit("8b 51"); c.bytes.push_back(static_cast<uint8_t>(4 + 4 * i));
        c.emit("85 d2"); c.branch("0f 84", next);
        c.emit("f3 0f 11 52 40"); c.label(next);
    }
    c.emit("f0 ff 05"); c.word(counter);
    c.label("done"); c.emit("58 5e c2 08 00");
    return c.finish(4096);
}

inline bool PartnerNearInside(float x, float y, float left, float top,
    float right, float bottom, float margin)
{
    constexpr float epsilon = 0.5f;
    return right > left && bottom > top && std::isfinite(x) && std::isfinite(y) &&
        x > left + margin + epsilon && x < right - margin - epsilon &&
        y > top + margin + epsilon && y < bottom - margin - epsilon;
}
}
