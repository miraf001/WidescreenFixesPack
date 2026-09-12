#include "stdafx.h"
#include "LEDEffects.h"
#include "CoopNativeCode.h"
#include <d3d9.h>
#include <d3dx9.h>
#pragma comment(lib, "d3dx9.lib")
#include <cmath>
#include <cstring>
#include <limits>
#include <vector>
#include <xinput.h>

constexpr auto defaultAspectRatio = 16.0f / 9.0f;
float fFOVFactor = 1.0f;
int32_t ResX = 0;
int32_t ResY = 0;
float fHudOffsetX = 0.0f;
float fHudOffsetY = 0.0f;
float fHudScaleX = 1.0f;
float fHudScaleY = 1.0f;
float fSubtitleOffsetX = 0.0f;
float fSubtitleOffsetY = 0.0f;
float fSubtitleScaleX = 1.0f;
float fSubtitleScaleY = 1.0f;
float fSubtitleLeftOffsetX = -0.25f;
float fSubtitleRightOffsetX = 0.25f;
bool bDualMonitorMode = false;
bool bSubtitlePerPlayer = false;

#if _DEBUG
alignas(8) volatile LONG64 gSubtitleTransformCalls = 0;
alignas(8) volatile LONG64 gSubtitleLastPeriodicLogTick = 0;
#endif

enum GUI
{
    uBioGUI__cResourceParam = 0x13BF0D8,
    uBioGUISubtitles = 0x13BBC30,
    uGUIAchieveCutin = 0x13977F0,
    uGUIActionIcon = 0x1391608,
    uGUIActionIcon2 = 0x13919C8,
    uGUIAppraise = 0x1391B70,
    uGUIAppraisePopup = 0x1391CD8,
    uGUIBonusGallery = 0x1392520,
    uGUIBonusOver = 0x13927B0,
    uGUIBonusPoint = 0x1392978,
    uGUIBonusRecord = 0x1392B70,
    uGUIBonusSettings = 0x1392E98,
    uGUIChallengeMedal = 0x1393790,
    uGUICommandBase = 0x139AA40,
    uGUICommandFar = 0x139AB98,
    uGUICommandNear = 0x139ACF8,
    uGUICommonMenu = 0x13950C8,
    uGUIComposePartsRaid__cParts = 0x1395C10,
    uGUIComsoon = 0x1396080,
    uGUIContinueInfo = 0x13961D8,
    uGUICustomCutin = 0x1396390,
    uGUICustomInfo = 0x1396570,
    uGUICustomWeapon__cWeapon = 0x13968B0,
    uGUICustomWeaponRaid = 0x1396BA0,
    uGUICutin = 0x1397950,
    uGUICWRPartsInfo = 0x1396D00,
    uGUICWRPartsList__cParts = 0x1396EA8,
    uGUICWRTipsBase = 0x1397030,
    uGUICWRWeaponInfo = 0x13971A0,
    uGUICWRWeaponList__cWeapon = 0x1397400,
    uGUIDamage = 0x1397DA0,
    uGUIDamage2 = 0x1397EF0,
    uGUIDamageNum = 0x139C028,
    uGUIDead = 0x1398040,
    uGUIDifficultySelect = 0x1398478,
    uGUIEpisode = 0x1398738,
    uGUIEpisodeEnd = 0x1398880,
    uGUIEpisodeEndEx = 0x1398B08,
    uGUIEpisodeHint = 0x1398CE8,
    uGUIEpisodeLogo = 0x1398E48,
    uGUIEpisodeTitle = 0x1398FF0,
    uGUIEquip = 0x139AE78,
    uGUIEquipShortcut = 0x139B008,
    uGUIEquipShortcutRaid = 0x139B1F8,
    uGUIEventCutIn = 0x1397AA0,
    uGUIExMarking = 0x139FB88,
    uGUIFade = 0x1399138,
    uGUIFileList = 0x13998B8,
    uGUIFileText = 0x1399A00,
    uGUIFlash = 0x139B5B0,
    uGUIFood = 0x139B710,
    uGUIGesture = 0x139B860,
    uGUIGetItem = 0x139D460,
    uGUIGuide = 0x1399E68,
    uGUIHeadLineNews = 0x139A8F0,
    uGUIHeal = 0x139B9F0,
    uGUIHealNum = 0x139BB48,
    uGUIIndicatorFar = 0x139C718,
    uGUIIndicatorNear = 0x139C860,
    uGUIInventoryCampaign__cCompose = 0x139CD20,
    uGUIInventoryRaid = 0x139D2E8,
    uGUIKeyItem = 0x139D640,
    uGUILoading = 0x139D830,
    uGUILoadingKafka = 0x139D980,
    uGUILoadingShow = 0x139DC10,
    uGUIManual = 0x139DFE8,
    uGUIMap = 0x139E148,
    uGUIMapDetailBase = 0x139F2B0,
    uGUIMapIcon = 0x139F9A0,
    uGUIMessageBox = 0x1398278,
    uGUIMissionClear = 0x13A0540,
    uGUIMissionFailed = 0x13A06A0,
    uGUIMissionStart = 0x13A0970,
    uGUIMoneyGuide = 0x1399FC8,
    uGUIMouseCursor = 0x13BF3F0,
    uGUIOnlineStore = 0x139FF68,
    uGUIPurpose = 0x139BC88,
    uGUIPuzzle = 0x13A0298,
    uGUIRaidBreakIn = 0x13A0400,
    uGUIRaidBuyCutin = 0x13A0AB8,
    uGUIRaidCutIn = 0x13A0C28,
    uGUIRaidDeparture = 0x13A10C0,
    uGUIRaidEquip = 0x139B460,
    uGUIRaidFormationBase = 0x13A1788,
    uGUIRaidFormationChar = 0x13A1978,
    uGUIRaidFormationGesture = 0x13A1AE0,
    uGUIRaidFormationSkill = 0x13A1CB8,
    uGUIRaidFormationWeapon = 0x13A1E38,
    uGUIRaidGetItemPopup = 0x13A0D78,
    uGUIRaidManualList = 0x13A1F90,
    uGUIRaidReady = 0x13A14E0,
    uGUIRaidReadyNew = 0x13A1620,
    uGUIRaidSkillPopup = 0x13A0EF8,
    uGUIRaidStore = 0x13A2828,
    uGUIRaidTop = 0x13A2A30,
    uGUIRaidVoiceList = 0x13A2598,
    uGUIRanking = 0x13A26D0,
    uGUIRankingCampaign = 0x13E84E8,
    uGUIRankingOption = 0x13A2B60,
    uGUIRankingRaid = 0x13A2CD0,
    uGUIReady = 0x13A2E30,
    uGUIReBanner = 0x13975D8,
    uGUIResult = 0x13A2F78,
    uGUIResultCutin = 0x13A30C8,
    uGUIResultCutinRaid = 0x13A3220,
    uGUIResultRaid = 0x13A34B0,
    uGUIResultRaidEvent = 0x13A3618,
    uGUIReticleBase = 0x13A38C0,
    uGUIReticleNatalia = 0x13A3A68,
    uGUIReticleScope = 0x13A3BC8,
    uGUIReticleThrow = 0x13A3D00,
    uGUISaving = 0x139DD80,
    uGUISearch = 0x13BAB38,
    uGUISessionCreat = 0x13A20D8,
    uGUISessionList = 0x13A2278,
    uGUISessionSearch = 0x13A2430,
    uGUISkill = 0x13BB710,
    uGUISkillCoolDown = 0x139BDF0,
    uGUIStaffRoll = 0x13BB8B8,
    uGUIStoreInfomation = 0x13A0128,
    uGUITextVoice = 0x13BEF88,
    uGUIThanks = 0x13BE7F0,
    uGUIThumbnail = 0x13BE938,
    uGUITimer = 0x13BEA88,
    uGUITitleTop = 0x13BEBD8,
    uGUITutorial = 0x13BEE38,
    uGUIVitalityEnemy = 0x139C178,
    uGUIVitalityMe = 0x139C2E0,
    uGUIVitalityPartner = 0x139C430,
    uGUIVoiceChatName = 0x13BF6E0,
    uGUIWeakPoint = 0x13BF848,
    VirtualScreen = 0x141AC10
};

static IDirect3DVertexShader9* g_screenVertexShader = nullptr;
static IDirect3DPixelShader9* g_wmvYuvDecodePixelShader = nullptr;
static IDirect3DVertexShader9* g_myScreenVertexShader = nullptr;
static SafetyHookInline gDualMonitorResetHook = {};
static SafetyHookInline gDualMonitorPresentHook = {};
static volatile LONG gDualMonitorPresentSerial = 0;
static volatile LONG gDualMonitorLastFmvPresentSerial =
    (std::numeric_limits<LONG>::min)() / 2;
static volatile LONG gDualMonitorLastFullCanvasBioSubtitlePresentSerial =
    (std::numeric_limits<LONG>::min)() / 2;
static thread_local float gSubtitlePassTranslationXNdc = 0.0f;
static thread_local float gSubtitlePassOffsetX = 0.0f;
// Only the second, replayed dual-monitor pause-menu pass sets this. Keeping it
// thread-local avoids touching a controller's native position while another
// GUI worker might be reading it.
static thread_local float gDualGuiPassTranslationXNdc = 0.0f;
// The FileText wrapper calls the shared renderer directly, but retain an
// explicit per-thread guard so nested GUI traversal can never duplicate the
// replay or observe it as a fresh left-side draw.
static thread_local bool gDualFileTextReplayActive = false;
static volatile LONG gActivePauseCommonMenu = 0;

void LoadHudTuningFromIni()
{
    CIniReader iniReader("");
    fHudOffsetX = iniReader.ReadFloat("HUD", "OffsetX", 0.0f);
    fHudOffsetY = iniReader.ReadFloat("HUD", "OffsetY", 0.0f);
    fHudScaleX = iniReader.ReadFloat("HUD", "ScaleX", 1.0f);
    fHudScaleY = iniReader.ReadFloat("HUD", "ScaleY", 1.0f);
    // Story subtitles are calibrated from the live full canvas in the renderer.
    // These INI values are deliberately only fine-tuning multipliers/offsets.
    bDualMonitorMode =
        iniReader.ReadInteger("COOP", "DualMonitorMode", 0) != 0;
    fSubtitleOffsetX = iniReader.ReadFloat("SUBTITLES", "OffsetX", 0.0f);
    fSubtitleOffsetY = iniReader.ReadFloat("SUBTITLES", "OffsetY", 0.0f);
    fSubtitleScaleX = iniReader.ReadFloat("SUBTITLES", "ScaleX", 1.0f);
    fSubtitleScaleY = iniReader.ReadFloat("SUBTITLES", "ScaleY", 1.0f);
    fSubtitleLeftOffsetX =
        iniReader.ReadFloat("SUBTITLES", "LeftOffsetX", -0.25f);
    fSubtitleRightOffsetX =
        iniReader.ReadFloat("SUBTITLES", "RightOffsetX", 0.25f);
    bSubtitlePerPlayer = bDualMonitorMode;
    DBGONLY(spd::log()->info(
        "[TUNING] HUD offset=({}, {}) scale=({}, {}); subtitles "
        "dualMonitor={} perPlayer={} offset=({}, {}) playerX=({}, {}) scale=({}, {})",
        fHudOffsetX, fHudOffsetY, fHudScaleX, fHudScaleY,
        bDualMonitorMode, bSubtitlePerPlayer,
        fSubtitleOffsetX, fSubtitleOffsetY,
        fSubtitleLeftOffsetX, fSubtitleRightOffsetX,
        fSubtitleScaleX, fSubtitleScaleY);)
}

namespace rev2coop
{
    inline void PollBridgeCapture();
    inline void Report(const char* message);
}
namespace dualmonitor { void PollInstall(); }

DWORD WINAPI IniHotkeyThread(LPVOID)
{
    while (true)
    {
        // If F5 is pressed
        if (GetAsyncKeyState(VK_F5) & 1)
        {
            LoadHudTuningFromIni();
            OutputDebugStringA("[HUD] Reloaded values from INI via F5\n");
        }

        dualmonitor::PollInstall();
        rev2coop::PollBridgeCapture();
        Sleep(20); // Bridge F9 synchronization stays off the game/render thread.
    }

    return 0;
}

bool IsSplitScreenActive()
{
    auto ptr = *(uint32_t*)0x157AE00;
    return ptr && *(uint32_t*)(ptr + 0x8F4) == 1;
}

int32_t GetResX()
{
    if (ResX)
        return ResX;
    else
        return *(int32_t*)(*(uint32_t*)0x15DE88C + 0x1E0);
}

int32_t GetResY()
{
    if (ResY)
        return ResY;
    else
        return *(int32_t*)(*(uint32_t*)0x15DE88C + 0x1E4);
}

int32_t GetRelativeResX()
{
    return 1280;
}

int32_t GetRelativeResY()
{
    return 720;
}

int32_t GetCurrentSplitScreenResX()
{
    return *(int32_t*)(*(uint32_t*)0x15DE88C + 0x50);
}

int32_t GetCurrentSplitScreenResY()
{
    return *(int32_t*)(*(uint32_t*)0x15DE88C + 0x54);
}

int32_t GetNativeSplitScreenResX()
{
    return 936 - 136;
}

int32_t GetNativeSplitScreenResY()
{
    return 360;
}

float GetAspectRatio()
{
    return (float)GetResX() / (float)GetResY();
}

float GetDiff()
{
    if (IsSplitScreenActive())
    {
        static constexpr float fDiffSplitScreen = (1280.0f / (936.0f - 136.0f));
        return (GetAspectRatio() / defaultAspectRatio) * fDiffSplitScreen;
    }
    else
    {
        return GetAspectRatio() / defaultAspectRatio;
    }
}

static bool IsRecentDualMonitorFmvFrame()
{
    if (!bDualMonitorMode || IsSplitScreenActive())
        return false;

    const auto presentSerial =
        InterlockedCompareExchange(&gDualMonitorPresentSerial, 0, 0);
    const auto fmvSerial =
        InterlockedCompareExchange(&gDualMonitorLastFmvPresentSerial, 0, 0);
    const auto delta = presentSerial - fmvSerial;
    return delta >= 0 && delta <= 1;
}

static bool IsRecentDualMonitorFullCanvasBioSubtitleFrame()
{
    if (!bDualMonitorMode || IsSplitScreenActive())
        return false;

    const auto presentSerial =
        InterlockedCompareExchange(&gDualMonitorPresentSerial, 0, 0);
    const auto subtitleSerial = InterlockedCompareExchange(
        &gDualMonitorLastFullCanvasBioSubtitlePresentSerial, 0, 0);
    const auto delta = presentSerial - subtitleSerial;
    return delta >= 0 && delta <= 1;
}

static bool GetPhysicalRendererSize(uint32_t& width, uint32_t& height)
{
    constexpr uintptr_t rendererPointer = 0x015E0388;
    constexpr uintptr_t rendererWidthOffset = 0xB8;
    constexpr uintptr_t rendererHeightOffset = 0xBC;

    width = 0;
    height = 0;
    if (IsBadReadPtr((void*)rendererPointer, sizeof(uintptr_t)))
        return false;

    const auto renderer = *reinterpret_cast<uintptr_t*>(rendererPointer);
    if (!renderer ||
        IsBadReadPtr((void*)(renderer + rendererHeightOffset), sizeof(uint32_t)))
    {
        return false;
    }

    width = *reinterpret_cast<uint32_t*>(renderer + rendererWidthOffset);
    height = *reinterpret_cast<uint32_t*>(renderer + rendererHeightOffset);
    return width >= 2 && (width & 1) == 0 && height != 0;
}

static bool IsBioSubtitleController(uintptr_t object);
static uintptr_t GetSubtitleController(uintptr_t object);

void __fastcall sub_96C410(int _this, int edx, int a2, int a3)
{
    int32_t v4 = 0, v5 = 0, v6 = 0, v7 = 0;
    auto dword_15DE88C = *(uint32_t*)0x15DE88C;

    if (*(uint8_t*)(_this + 144))
    {
        v4 = *(int32_t*)(dword_15DE88C + 3248);
        v5 = *(int32_t*)(dword_15DE88C + 3252);
        v6 = *(int32_t*)(dword_15DE88C + 3256);
        v7 = *(int32_t*)(dword_15DE88C + 3260);
    }
    else
    {
        auto v8 = 400 * *(uint32_t*)(_this + 140);
        v4 = *(int32_t*)(v8 + dword_15DE88C + 72);
        v5 = *(int32_t*)(v8 + dword_15DE88C + 76);
        v6 = *(int32_t*)(v8 + dword_15DE88C + 80);
        v7 = *(int32_t*)(v8 + dword_15DE88C + 84);
    }

    auto v9 = (float)(v7 - v5) * 0.0013888889f;
    auto v10 = (float)(v6 - v4) * 0.00078125001f;
    if (v10 <= v9)
        v9 = v10;

    if (IsSplitScreenActive())
        a2 += (int32_t)((720.0f * GetAspectRatio()) - (1280.0f / (1280.0f / GetNativeSplitScreenResX())));
    else
        a2 += (int32_t)(((720.0f * GetAspectRatio()) - 1280.0f) / 2.0f);

    *(int32_t*)(_this + 164) = (int32_t)(((float)a2 * v9) + (float)v4);
    *(int32_t*)(_this + 168) = (int32_t)(((float)a3 * v9) + (float)v5);
}

enum
{
    RESCALE = 0xAAAAEEEE,
    STRETCH = 0xBBBBFFFF,
    OFFSET = 0xCCCCDDDD,
    SUBTITLES = 0xDDDDDDDD,
    FADE_STRETCH = 0xEEEEDDDD,
};

void __fastcall sub_E18040(int _this, int edx, int a2)
{
    char* v2; // esi
    float v4; // xmm5_4
    float v5; // xmm6_4
    float v6; // xmm7_4
    float v7; // xmm0_4
    int v8; // ecx
    uint32_t* v9; // eax
    int v10; // edi
    int v11; // ecx
    int v12; // ecx
    float* v13; // edx
    float v14; // xmm4_4
    float v15; // xmm3_4
    int v16; // eax
    int v17; // edi
    float v18; // xmm0_4
    int v19; // [esp+8h] [ebp-3Ch]
    float v20; // [esp+8h] [ebp-3Ch]
    int v21; // [esp+Ch] [ebp-38h]
    int v22; // [esp+10h] [ebp-34h]
    int v23; // [esp+14h] [ebp-30h]
    int v24; // [esp+18h] [ebp-2Ch]
    int v25; // [esp+18h] [ebp-2Ch]
    float v26; // [esp+1Ch] [ebp-28h]
    float v27; // [esp+28h] [ebp-1Ch]
    int v28; // [esp+2Ch] [ebp-18h]
    int v29; // [esp+30h] [ebp-14h]

    auto sub_D7A340 = (int(__fastcall*) (char*, int, int))0xD7A340;
    auto sub_D79650 = (float(__fastcall*) (char*, int))0xD79650;
    auto sub_D79630 = (float(__fastcall*) (char*, int))0xD79630;
    auto sub_E67E20 = (void(__fastcall*) (uint32_t*, int, int))0xE67E20;

    v2 = *(char**)(a2 + 4);
    v19 = *(uint32_t*)0x15DDFD8;
    v21 = *(uint32_t*)0x15DDFDC + *((uint32_t*)v2 + 50) - *((uint32_t*)v2 + 48);
    v29 = *(uint32_t*)0x15DDFDC;
    v24 = *(uint32_t*)0x15DDFDC;
    v28 = *(uint32_t*)0x15DDFD8 + *((uint32_t*)v2 + 49) - *((uint32_t*)v2 + 47);
    v4 = *(float*)(_this + 0x60) * *(float*)&*(uint32_t*)0x153C628;
    v5 = *(float*)(_this + 100) * *(float*)&*(uint32_t*)0x153C62C;
    v6 = *(float*)(_this + 64);
    v7 = *(float*)(_this + 68);
    v22 = *(uint32_t*)0x15DDFD8;
    v8 = v28;
    v23 = v21;
    v9 = *(uint32_t**)(_this + 240);
    v10 = 2;
    v26 = v4;
    v27 = v5;
    if (v9)
    {
        v8 = v9[30];
        v10 = (v9[28] >> 1) & 3;
        v23 = v9[31];
        v22 = 0;
        v24 = 0;
    }
    if ((*(uint32_t*)(_this + 328) & 4) != 0)
    {
        v4 = (float)((float)(*((uint32_t*)v2 + 49) - *((uint32_t*)v2 + 47)) / (float)(v8 - v22)) * v4;
        v26 = v4;
        v27 = (float)((float)(*((uint32_t*)v2 + 50) - *((uint32_t*)v2 + 48)) / (float)(v23 - v24)) * v5;
        v5 = v27;
    }
    *((uint32_t*)v2 + 19) |= 2u;
    if (v2[76] < 0)
    {
        *(uint32_t*)&v2[12 * *((uint32_t*)v2 + 23) + 199884] = *(uint32_t*)&v2[12 * *((uint32_t*)v2 + 23) + 199884] & 0x80000000 | 0x2C4;
        *(uint32_t*)&v2[12 * *((uint32_t*)v2 + 23) + 199884] &= ~0x80000000;
        v11 = 3 * *((uint32_t*)v2 + 23);
        *(uint32_t*)&v2[4 * v11 + 199888] = *((uint32_t*)v2 + 1542);
        *(uint32_t*)&v2[4 * v11 + 199892] = *((uint32_t*)v2 + 1543);
        ++*((uint32_t*)v2 + 23);
    }
    v12 = (4 * *(uint16_t*)(*(uint32_t*)(*((uint32_t*)v2 + 2) + 2832) + 24) + 15) & 0xFFFFFFF0;
    v25 = v12;
    if ((unsigned int)(v12 + *((uint32_t*)v2 + 5)) > *((uint32_t*)v2 + 6))
    {
        sub_D7A340(v2, edx, v12);
        v4 = v26;
        v5 = v27;
        v12 = v25;
    }
    v13 = (float*)*((uint32_t*)v2 + 5);
    *(char**)((uint32_t*)v2 + 5) = (char*)v13 + v12;
    *(float**)((uint32_t*)v2 + 1542) = v13;
    *((uint32_t*)v2 + 81) |= 1u;
    if (v13)
    {
        v14 = 2.0f / (float)(v28 - v19);
        v15 = -2.0f / (float)(v21 - v29);
        v13[0] = v14 * v4;
        v13[1] = v15 * v5;
        v13[2] = (float)(v14 * v6) - 1.0f;
        v13[3] = (float)(v15 * v7) + 1.0f;
        *((uint32_t*)v2 + 19) &= ~2u;

        switch (edx)
        {
        case SUBTITLES:
        case RESCALE:
        {
            if (IsSplitScreenActive())
            {
                const float screenWidth = (float)(v28 - v19);
                const float screenHeight = (float)(v21 - v29);
                const auto splitWidth = GetCurrentSplitScreenResX();
                const bool isLeftViewportOrigin = v19 == 0 || v19 == 1;
                const bool isRightViewportOrigin =
                    v19 == splitWidth || v19 == splitWidth + 1;
                const auto viewportWidth = v28 - v19;
                const bool isOneViewportWide =
                    viewportWidth >= splitWidth - 1 &&
                    viewportWidth <= splitWidth + 1;
                const bool isSplitViewport = isOneViewportWide &&
                    (isLeftViewportOrigin || isRightViewportOrigin);
                const bool isSubtitles = edx == SUBTITLES;

                // Full-screen GUI such as the pause-menu overlay also starts
                // at X=0. Its full-canvas width distinguishes it from player
                // one's HUD viewport. Leave those elements on the canonical
                // transform initialized above; only actual half-width HUD
                // viewports receive the split-screen HUD correction.
                if (isSubtitles || isSplitViewport)
                {
                    v14 = 2.0f / (float)(v28 - v19);
                    v15 = -2.0f / (float)(v21 - v29);

                    if (isSubtitles)
                    {
                        // The native co-op GUI correction narrows subtitles by
                        // 1280/800. Reconstruct the single-player transform
                        // from the current full canvas, never from a fixed
                        // 1920x1080 offset.
                        const float splitAspectFix = 1.0f / GetDiff();
                        const float spAspectFix =
                            defaultAspectRatio / GetAspectRatio();
                        const float automaticScaleX =
                            spAspectFix / splitAspectFix;
                        const float automaticOffsetX =
                            (splitAspectFix - spAspectFix) * 0.5f;
                        // The live 3840x1080 calibration exposed one more
                        // full-canvas correction which is proportional to the
                        // actual aspect, not to a particular monitor width.
                        // At 3840x1080 these evaluate to ScaleX=2.5 and
                        // OffsetX=-0.0625 -- the visually confirmed values.
                        constexpr float subtitleScalePerAspect = 45.0f / 64.0f;
                        const float dynamicSubtitleScaleX =
                            (screenWidth / screenHeight) * subtitleScalePerAspect;
                        const float dynamicSubtitleOffsetX =
                            -2.0f * screenHeight / (9.0f * screenWidth);
                        const float offsetX = screenWidth *
                            (automaticOffsetX + dynamicSubtitleOffsetX +
                             fSubtitleOffsetX + gSubtitlePassOffsetX);
                        const float offsetY = screenHeight * fSubtitleOffsetY;
                        v13[0] = v14 * v4 * splitAspectFix *
                            automaticScaleX * dynamicSubtitleScaleX *
                            fSubtitleScaleX;
                        v13[1] = v15 * v5 * fSubtitleScaleY;
                        v13[2] = (v14 * (v6 + offsetX)) - splitAspectFix +
                            gSubtitlePassTranslationXNdc;
                        v13[3] = (v15 * (v7 + offsetY)) + 1.0f;
                    }
                    else
                    {
                        constexpr float baseOffsetXFactor = -0.0f;
                        constexpr float baseOffsetYFactor = 0.25f;
                        constexpr float baseScaleX = 0.8f;
                        constexpr float baseScaleY = 1.0f;
                        const float baseOffsetX =
                            screenWidth * baseOffsetXFactor;
                        const float baseOffsetY =
                            screenHeight * baseOffsetYFactor;
                        const float offsetX = screenWidth * fHudOffsetX;
                        const float offsetY = screenHeight * fHudOffsetY;
                        v13[0] = v14 * v4 * baseScaleX * fHudScaleX;
                        v13[1] = v15 * v5 * baseScaleY * fHudScaleY;
                        v13[2] = (v14 * (v6 + baseOffsetX + offsetX)) - 1.0f;
                        v13[3] = (v15 * (v7 + baseOffsetY + offsetY)) + 1.0f;
                    }
                }
            }
            else
            {
                v14 = 2.0f / (float)(v28 - v19);
                v15 = -2.0f / (float)(v21 - v29);
                // Subtitle tuning is intentionally split-screen-only. Preserve
                // the original single-player transform and placement.
                v13[0] = v14 * v4;
                v13[1] = v15 * v5;
                v13[2] = (float)(v14 * v6) - (1.0f / GetDiff());
                v13[3] = (float)(v15 * v7) + 1.0f;
            }

            // Active FMVs are drawn from a full-canvas subtitle transform but
            // their video is mapped into the left monitor. Apply that same
            // horizontal scale once to their subtitle transform.
            if (edx == SUBTITLES && IsRecentDualMonitorFmvFrame())
            {
                constexpr float equalMonitorLeftFraction = 1.0f / 2.0f;
                v13[0] *= equalMonitorLeftFraction;
            }

            if (edx == SUBTITLES && bDualMonitorMode &&
                !IsSplitScreenActive())
            {
                uint32_t physicalWidth = 0;
                uint32_t physicalHeight = 0;
                const auto subtitleController =
                    GetSubtitleController((uintptr_t)_this);
                const bool isBioSubtitle =
                    IsBioSubtitleController(subtitleController);
                const auto rawViewportWidth = v28 - v19;
                const bool hasPhysicalCanvas = GetPhysicalRendererSize(
                    physicalWidth, physicalHeight);
                const bool isFullCanvas = hasPhysicalCanvas &&
                    rawViewportWidth > static_cast<int32_t>(physicalWidth / 2 + 1);

                // A full-canvas uBioGUISubtitles pass is the stable marker for
                // the long in-engine cutscene path. Ordinary SP has only a
                // full-canvas TextVoice pass; the short in-engine scene is
                // already W/2-local. Keep the marker for the current/previous
                // Present because TextVoice and Bio can arrive in either order.
                if (isFullCanvas && isBioSubtitle)
                {
                    InterlockedExchange(
                        &gDualMonitorLastFullCanvasBioSubtitlePresentSerial,
                        InterlockedCompareExchange(
                            &gDualMonitorPresentSerial, 0, 0));
                }

                if (isFullCanvas &&
                    IsRecentDualMonitorFullCanvasBioSubtitleFrame())
                {
                    const float absoluteScaleY = std::fabs(v13[1]);
                    if (absoluteScaleY > 0.000000001f)
                    {
                        const float observedRatio =
                            std::fabs(v13[0]) / absoluteScaleY;
                        // Bio uses Capcom's canonical 1280x720 transform;
                        // TextVoice uses the current physical canvas. Compare
                        // ratios rather than pixel constants so the guard also
                        // works at other equal-monitor resolutions.
                        const float expectedFullRatio = isBioSubtitle
                            ? (720.0f / 1280.0f)
                            : (static_cast<float>(physicalHeight) /
                               static_cast<float>(physicalWidth));
                        const float expectedHalfRatio =
                            expectedFullRatio * 0.5f;
                        const bool alreadyLeftScaled =
                            std::fabs(observedRatio - expectedHalfRatio) <
                            std::fabs(observedRatio - expectedFullRatio);

                        // During an active FMV the block above already applied
                        // 0.5, so do not halve it again. A paused FMV and the
                        // long in-engine cutscene have the unscaled full ratio
                        // and receive exactly one correction here.
                        if (!alreadyLeftScaled)
                            v13[0] *= 0.5f;
                    }
                }
            }

            // The dual-monitor pause wrappers replay an otherwise native
            // full-canvas GUI transform. Move only their second draw in NDC;
            // no controller coordinates or cached layout data are mutated.
            if (edx == RESCALE && gDualGuiPassTranslationXNdc != 0.0f)
                v13[2] += gDualGuiPassTranslationXNdc;

            DBGONLY({
                if (edx == SUBTITLES)
                {
                    const bool splitScreenActive = IsSplitScreenActive();
                    static int singleScreenTraceCount = 0;
                    static int splitScreenTraceCount = 0;
                    int& subtitleTraceCount = splitScreenActive ? splitScreenTraceCount : singleScreenTraceCount;
                    const int subtitleTraceLimit = splitScreenActive ? 64 : 8;
                    if (subtitleTraceCount++ < subtitleTraceLimit)
                    {
                        const char* branch = "unmatched";
                        if (!splitScreenActive)
                            branch = "single-screen";
                        else if ((v28 - v19) > GetCurrentSplitScreenResX() + 1)
                            branch = "shared-full-canvas";
                        else if (v19 == 0 || v19 == 1)
                            branch = "left";
                        else if (v19 == GetCurrentSplitScreenResX() || v19 == GetCurrentSplitScreenResX() + 1)
                            branch = "right";

                        spd::log()->info(
                            "[SUBTITLES] branch={} bounds=({}, {})-({}, {}) split={}x{} screen={}x{} "
                            "inputScale=({}, {}) inputPos=({}, {}) output=({}, {}, {}, {})",
                            branch, v19, v29, v28, v21,
                            GetCurrentSplitScreenResX(), GetCurrentSplitScreenResY(), GetResX(), GetResY(),
                            v4, v5, v6, v7, v13[0], v13[1], v13[2], v13[3]);
                    }
                }
            });
        }
        break;
        case STRETCH:
        case FADE_STRETCH:
        {
            v14 = (2.0f * GetDiff()) / (float)(v28 - v19);
            v15 = -2.0f / (float)(v21 - v29);
            v13[0] = v14 * v4;
            v13[1] = v15 * v5;
            v13[2] = -1.0f; //(float)(v14 * v6) - fDiffInv;
            v13[3] = (float)(v15 * v7) + 1.0f;

            if (edx == FADE_STRETCH && IsSplitScreenActive())
            {
                // uGUIFade's geometry is always 720 logical units high.
                // Its legacy STRETCH path divided by the physical height, so
                // a 1080p co-op fade covered only 720/1080 (two thirds) of
                // each viewport. Keep its separately verified X correction
                // intact and scale only the native Y geometry/offset.
                constexpr float nativeFadeHeight = 720.0f;
                const float heightFactor =
                    (float)(v21 - v29) / nativeFadeHeight;
                v13[1] *= heightFactor;
                v13[3] = ((v13[3] - 1.0f) * heightFactor) + 1.0f;
            }
        }
        break;
        case OFFSET:
        {
            if (IsSplitScreenActive())
            {
                if (v21 == GetCurrentSplitScreenResY() || v21 == (GetCurrentSplitScreenResY() + 1))
                {
                    v14 = 2.0f / (float)(v28 - v19);
                    v15 = -2.0f / (float)(v21 - v29);
                    v13[0] = v14 * v4;
                    v13[1] = v15 * v5;
                    v13[2] = (float)(v14 * v6) - (1.0f / GetDiff());
                    v13[3] = (float)(v15 * v7) + 1.0f;
                }
                else if (v21 == GetResY())
                {
                    v14 = 2.0f / (float)(v28 - v19);
                    v15 = -2.0f / (float)(v21 - v29);
                    v13[0] = v14 * v4;
                    v13[1] = v15 * v5;
                    v13[2] = (float)(v14 * v6) - (1.0f / (GetAspectRatio() / defaultAspectRatio));
                    v13[3] = (float)(v15 * v7) + 1.0f;
                }
            }
            else
            {
                if (v21 == GetResY())
                {
                    v14 = 2.0f / (float)(v28 - v19);
                    v15 = -2.0f / (float)(v21 - v29);
                    v13[0] = v14 * v4;
                    v13[1] = v15 * v5;
                    v13[2] = (float)(v14 * v6) - (1.0f / GetDiff());
                    v13[3] = (float)(v15 * v7) + 1.0f;
                }
            }
        }
        break;
        default:
            break;
        }
    }
    v16 = a2;
    *(float*)(a2 + 184) = v6;
    *(float*)(a2 + 188) = v7;
    *(float*)(a2 + 192) = v4;
    *(float*)(a2 + 196) = v5;
    v17 = v10 - 1;
    if (!v17)
    {
        v20 = sub_D79650(v2, edx);
    LABEL_18:
        v18 = v20;
        goto LABEL_19;
    }
    if (v17 != 1)
    {
        v18 = 0.0;
        goto LABEL_20;
    }
    v20 = sub_D79630(v2, edx);
    if ((uint8_t) * ((uint32_t*)v2 + 86) < 8u
        && !*(uint32_t*)(400 * (uint8_t) * ((uint32_t*)v2 + 86) + *(uint32_t*)0x15DE88C + 52))
    {
        goto LABEL_18;
    }
    v18 = v20 + 0.25f;
LABEL_19:
    v16 = a2;
LABEL_20:
    *(float*)(v16 + 96) = v18;
    if ((*(uint8_t*)(_this + 328) & 1) != 0)
    {
        if (*(uint32_t*)(_this + 244))
        {
            *((uint32_t*)v2 + 85) = *((uint32_t*)v2 + 85) & 0x1F ^ (32
                * (*(uint32_t*)(_this + 332) + (*(uint32_t*)(_this + 336) << 20)));
            sub_E67E20(*(uint32_t**)(_this + 244), edx, a2);
        }
    }
}

void __fastcall sub_E18040_nop(int _this, int edx, int a2)
{
    return;
}

static bool IsTextVoiceController(uintptr_t object)
{
    constexpr uintptr_t uGUITextVoiceVtable = uGUITextVoice - 0x58;

    if (!object || IsBadReadPtr((void*)object, sizeof(uintptr_t)))
        return false;

    return *(uintptr_t*)object == uGUITextVoiceVtable;
}

static bool IsBioSubtitleController(uintptr_t object)
{
    constexpr uintptr_t classNameOffset = 0x1B8;

    if (!object || IsBadReadPtr((void*)object, sizeof(uintptr_t)))
        return false;

    const auto vtable = *(uintptr_t*)object;

    if (!vtable || IsBadReadPtr((void*)(vtable + classNameOffset), sizeof("uBioGUISubtitles")))
        return false;

    const auto className = (const char*)(vtable + classNameOffset);
    return std::memcmp(className, "uBioGUISubtitles", sizeof("uBioGUISubtitles")) == 0;
}

static bool IsSubtitleController(uintptr_t object)
{
    return IsTextVoiceController(object) || IsBioSubtitleController(object);
}

enum class SubtitleViewportSide
{
    Automatic,
    Left,
    Right,
};

static SubtitleViewportSide GetLinkedSubtitleViewportSide(uintptr_t controller)
{
    constexpr uintptr_t nextControllerOffset = 0x14;
    constexpr uintptr_t previousControllerOffset = 0x18;

    // Story subtitles (uGUITextVoice) are rendered twice from their one native
    // geometry buffer and must remain on the shared canvas. Only the game's
    // already-linked uBioGUISubtitles objects use per-viewport classification.
    if (!IsBioSubtitleController(controller) ||
        IsBadReadPtr((void*)(controller + previousControllerOffset), sizeof(uintptr_t)))
    {
        return SubtitleViewportSide::Automatic;
    }

    const auto nextController = *(uintptr_t*)(controller + nextControllerOffset);
    if (nextController != controller && IsBioSubtitleController(nextController))
        return SubtitleViewportSide::Left;

    const auto previousController = *(uintptr_t*)(controller + previousControllerOffset);
    if (previousController != controller && IsBioSubtitleController(previousController))
        return SubtitleViewportSide::Right;

    return SubtitleViewportSide::Automatic;
}

#if 0 // Superseded: native TextVoice geometry is replayed instead of cloned.
static uintptr_t EnsureTextVoiceClone(uintptr_t controller)
{
    constexpr uintptr_t nextControllerOffset = 0x14;
    constexpr uintptr_t previousControllerOffset = 0x18;
    constexpr uintptr_t createTextVoiceAddress = 0x00967B50;

    if (!IsTextVoiceController(controller) ||
        controller != gTextVoicePrimaryController ||
        IsBadReadPtr((void*)(controller + previousControllerOffset), sizeof(uintptr_t)))
    {
        return 0;
    }


    const auto registeredClone = gTextVoiceCloneController;
    if (IsTextVoiceController(registeredClone))
        return registeredClone;

    // E18040 can run concurrently on several render workers. Only one of them
    // may allocate and splice the clone into the intrusive GUI object list.
    if (InterlockedCompareExchange(&gTextVoiceCloneCreationState, 1, 0) != 0)
        return 0;

    const auto nextController = *(uintptr_t*)(controller + nextControllerOffset);
    if (nextController != controller && IsTextVoiceController(nextController))
    {
        gTextVoiceCloneController = nextController;
        InterlockedExchange(&gTextVoiceCloneCreationState, 2);
        return nextController;
    }

    const auto previousController = *(uintptr_t*)(controller + previousControllerOffset);
    if (previousController != controller && IsTextVoiceController(previousController))
    {
        InterlockedExchange(&gTextVoiceCloneCreationState, 0);
        return 0;
    }

    const auto createTextVoice =
        reinterpret_cast<void* (__cdecl*)()>(createTextVoiceAddress);
    const auto clone = reinterpret_cast<uintptr_t>(createTextVoice());
    if (!IsTextVoiceController(clone))
    {
        InterlockedExchange(&gTextVoiceCloneCreationState, 0);
        return 0;
    }

    // uGUI instances of one class form the manager's intrusive list through
    // +0x14/+0x18. Inserting a freshly constructed object here lets the native
    // manager perform activation and asynchronous resource loading itself.
    *(uintptr_t*)(clone + nextControllerOffset) = nextController;
    *(uintptr_t*)(clone + previousControllerOffset) = controller;
    if (nextController &&
        !IsBadReadPtr((void*)(nextController + previousControllerOffset), sizeof(uintptr_t)))
    {
        *(uintptr_t*)(nextController + previousControllerOffset) = clone;
    }
    *(uintptr_t*)(controller + nextControllerOffset) = clone;
    gTextVoiceCloneController = clone;
    InterlockedExchange(&gTextVoiceCloneCreationState, 2);

    DBGONLY(spd::log()->info(
        "[TEXTVOICE-PAIR] linked primary=0x{:08X} clone=0x{:08X} oldNext=0x{:08X}",
        static_cast<uint32_t>(controller), static_cast<uint32_t>(clone),
        static_cast<uint32_t>(nextController));)
    return clone;
}

static void SynchronizeTextVoiceCloneState(uintptr_t controller, uintptr_t clone)
{
    constexpr uintptr_t guiStateFlagsOffset = 0x148;
    constexpr uint32_t guiEnabledAndDirtyMask = 0x201;
    constexpr uintptr_t voiceStateOffsets[] = {
        0x25C, // current outer state
        0x260, // current inner state
        0x264, // requested outer state
        0x268, // requested inner state
        0x26C, // previous outer state
    };

    // 0x968DF0 only dispatches the native TextVoice layout callback while bit
    // zero is set. A factory-created clone otherwise remains at 0x1000 and is
    // reset to its idle state every frame, even though its text buffer already
    // contains the mirrored string. Copy the primary object's enabled/dirty
    // bits so the clone can build and update its own glyph geometry.
    const auto primaryFlags =
        *reinterpret_cast<const uint32_t*>(controller + guiStateFlagsOffset);
    auto& cloneFlags =
        *reinterpret_cast<uint32_t*>(clone + guiStateFlagsOffset);
    cloneFlags = (cloneFlags & ~guiEnabledAndDirtyMask) |
        (primaryFlags & guiEnabledAndDirtyMask);

    for (const auto offset : voiceStateOffsets)
    {
        *reinterpret_cast<uint32_t*>(clone + offset) =
            *reinterpret_cast<const uint32_t*>(controller + offset);
    }
}

static void MirrorTextVoiceEvent(
    SafetyHookInline& hook, void* object, void* edx, const char* eventName)
{
    const auto controller = reinterpret_cast<uintptr_t>(object);
    const auto viewportSide = GetLinkedSubtitleViewportSide(controller);

    // Run the native event on the object selected by the game first. Calling
    // through SafetyHook's trampoline avoids entering this detour recursively.
    hook.unsafe_fastcall<void>(object, edx);

    if (!IsSplitScreenActive() || viewportSide != SubtitleViewportSide::Left)
        return;

    constexpr uintptr_t nextControllerOffset = 0x14;
    constexpr uintptr_t guiRootOffset = 0xF4;
    constexpr uintptr_t textNodeOffset = 0x2C4;
    const auto clone = *(uintptr_t*)(controller + nextControllerOffset);
    if (!IsTextVoiceController(clone) ||
        IsBadReadPtr((void*)(clone + textNodeOffset), sizeof(uintptr_t)) ||
        !*(uintptr_t*)(clone + guiRootOffset) ||
        !*(uintptr_t*)(clone + textNodeOffset))
    {
        DBGONLY(spd::log()->warn(
            "[TEXTVOICE-EVENT] {} not mirrored; clone is not resource-ready",
            eventName);)
        return;
    }

    constexpr uintptr_t layoutModeOffset = 0x2B1;
    SynchronizeTextVoiceCloneState(controller, clone);
    *reinterpret_cast<uint8_t*>(clone + layoutModeOffset) =
        *reinterpret_cast<uint8_t*>(controller + layoutModeOffset);

    hook.unsafe_fastcall<void>(reinterpret_cast<void*>(clone), nullptr);
}

void __fastcall TextVoiceVoiceStop(void* object, void* edx)
{
    MirrorTextVoiceEvent(gTextVoiceVoiceStopHook, object, edx, "stop");
}

void __fastcall TextVoiceVoiceStart(void* object, void* edx)
{
    MirrorTextVoiceEvent(gTextVoiceVoiceStartHook, object, edx, "start");
}

void __fastcall TextVoiceVoiceAdvance(void* object, void* edx)
{
    MirrorTextVoiceEvent(gTextVoiceVoiceAdvanceHook, object, edx, "advance");
}

void __fastcall TextVoiceVoiceReset(void* object, void* edx)
{
    MirrorTextVoiceEvent(gTextVoiceVoiceResetHook, object, edx, "reset");
}

void __stdcall TextVoiceSetText(void* textNode, const char* text)
{
    constexpr uintptr_t ownerControllerOffset = 0x74;
    constexpr uintptr_t nextControllerOffset = 0x14;
    constexpr uintptr_t textNodeOffset = 0x2C4;

    const auto node = reinterpret_cast<uintptr_t>(textNode);
    uintptr_t controller = 0;
    if (node && !IsBadReadPtr(
            reinterpret_cast<void*>(node + ownerControllerOffset), sizeof(uintptr_t)))
    {
        controller = *reinterpret_cast<uintptr_t*>(node + ownerControllerOffset);
    }

    gTextVoiceSetTextHook.unsafe_stdcall<void>(textNode, text);

    if (!IsSplitScreenActive() || !IsTextVoiceController(controller) ||
        GetLinkedSubtitleViewportSide(controller) != SubtitleViewportSide::Left)
    {
        return;
    }

    const auto clone = *reinterpret_cast<uintptr_t*>(controller + nextControllerOffset);
    if (!IsTextVoiceController(clone))
        return;

    const auto cloneTextNode = *reinterpret_cast<uintptr_t*>(clone + textNodeOffset);
    if (!cloneTextNode || cloneTextNode == node)
        return;

    SynchronizeTextVoiceCloneState(controller, clone);

    // 0x969E40 consumes the string synchronously and rebuilds the destination
    // text node. Replaying the same call is safe even when `text` points to a
    // temporary localization buffer because it happens before the caller returns.
    gTextVoiceSetTextHook.unsafe_stdcall<void>(
        reinterpret_cast<void*>(cloneTextNode), text);
    DBGONLY(spd::log()->info(
        "[TEXTVOICE-TEXT] primaryNode=0x{:08X} cloneNode=0x{:08X} "
        "primaryFlags=0x{:08X} cloneFlags=0x{:08X} text={}",
        static_cast<uint32_t>(node), static_cast<uint32_t>(cloneTextNode),
        *reinterpret_cast<const uint32_t*>(controller + 0x148),
        *reinterpret_cast<const uint32_t*>(clone + 0x148),
        text ? text : "<null>");)
}
#endif

static void RenderSubtitleAtSplitViewport(
    int object, int a2, SubtitleViewportSide side, bool forceHalfWidth)
{
    constexpr uintptr_t contextOffset = 0x04;
    constexpr uintptr_t leftBoundOffset = 47 * sizeof(uint32_t);
    constexpr uintptr_t rightBoundOffset = 49 * sizeof(uint32_t);

    auto& viewportOriginX = *(int32_t*)0x15DDFD8;
    const auto originalViewportOriginX = viewportOriginX;
    const auto originalPassTranslationXNdc = gSubtitlePassTranslationXNdc;
    const auto splitWidth = GetCurrentSplitScreenResX();
    const bool usesHalfPixelOrigin = originalViewportOriginX == 1 ||
        originalViewportOriginX == splitWidth + 1;

    uintptr_t renderContext = 0;
    int32_t originalRightBound = 0;
    bool changedRightBound = false;
    if (forceHalfWidth && a2 && !IsBadReadPtr((void*)(a2 + contextOffset), sizeof(uintptr_t)))
    {
        renderContext = *(uintptr_t*)(a2 + contextOffset);
        if (renderContext &&
            !IsBadReadPtr((void*)(renderContext + rightBoundOffset), sizeof(int32_t)))
        {
            const auto leftBound = *(int32_t*)(renderContext + leftBoundOffset);
            auto& rightBound = *(int32_t*)(renderContext + rightBoundOffset);
            originalRightBound = rightBound;
            if (rightBound - leftBound != splitWidth)
            {
                rightBound = leftBound + splitWidth;
                changedRightBound = true;
            }
        }
    }

    viewportOriginX = (side == SubtitleViewportSide::Right ? splitWidth : 0) +
        (usesHalfPixelOrigin ? 1 : 0);

    // The GUI renderer queues this transform and does not retain a temporary
    // D3D viewport change. Keep both copies in the main split-screen pass and
    // place the right copy one half-screen (1.0 full-screen NDC) to the right.
    // txt_voice uses a 640-wide logical center, so apply the same local center
    // correction to both copies before separating them.
    constexpr float textVoiceCenterCorrectionXNdc = -0.20833333f;
    gSubtitlePassTranslationXNdc =
        (forceHalfWidth && side == SubtitleViewportSide::Right ? 1.0f : 0.0f) +
        (forceHalfWidth ? textVoiceCenterCorrectionXNdc : 0.0f);

    sub_E18040(object, SUBTITLES, a2);
    gSubtitlePassTranslationXNdc = originalPassTranslationXNdc;
    viewportOriginX = originalViewportOriginX;

    if (changedRightBound)
        *(int32_t*)(renderContext + rightBoundOffset) = originalRightBound;
}

static uintptr_t GetSubtitleController(uintptr_t object)
{
    constexpr uintptr_t ownerOffset = 0x6C;

    if (IsSubtitleController(object))
        return object;

    if (!object || IsBadReadPtr((void*)(object + ownerOffset), sizeof(uintptr_t)))
        return 0;

    const auto owner = *(uintptr_t*)(object + ownerOffset);
    return owner != object && IsSubtitleController(owner) ? owner : 0;
}

static void RenderTextVoiceForBothViewports(int object, int a2)
{
    const auto originalPassOffsetX = gSubtitlePassOffsetX;

    // The game owns one story-subtitle geometry buffer. Replaying its normal
    // transform/draw path queues that already-built geometry twice without
    // cloning the TextVoice object or its fragile native lifecycle state.
    gSubtitlePassOffsetX = originalPassOffsetX + fSubtitleLeftOffsetX;
    sub_E18040(object, SUBTITLES, a2);
    gSubtitlePassOffsetX = originalPassOffsetX + fSubtitleRightOffsetX;
    sub_E18040(object, SUBTITLES, a2);

    gSubtitlePassOffsetX = originalPassOffsetX;
}

void __fastcall sub_E18040_rescale(int _this, int edx, int a2)
{
    const bool splitScreenActive = IsSplitScreenActive();
    const auto subtitleController = GetSubtitleController((uintptr_t)_this);

    if (subtitleController)
    {
        const auto linkedViewportSide =
            GetLinkedSubtitleViewportSide(subtitleController);
        const auto subtitleViewportSide = splitScreenActive
            ? linkedViewportSide
            : SubtitleViewportSide::Automatic;

        DBGONLY({
            const LONG64 callCount = InterlockedIncrement64(&gSubtitleTransformCalls);
            const LONG64 now = static_cast<LONG64>(GetTickCount64());
            const LONG64 previousLogTick = InterlockedCompareExchange64(
                &gSubtitleLastPeriodicLogTick, 0, 0);
            if (now - previousLogTick >= 1000 &&
                InterlockedCompareExchange64(
                    &gSubtitleLastPeriodicLogTick, now, previousLogTick) == previousLogTick)
            {
                D3DVIEWPORT9 viewport = {};
                RECT scissor = {};
                DWORD scissorEnabled = FALSE;
                HRESULT viewportResult = E_FAIL;
                HRESULT scissorResult = E_FAIL;
                HRESULT scissorStateResult = E_FAIL;

                const auto renderer = *(uintptr_t*)0x15E0388;
                if (renderer && !IsBadReadPtr((void*)(renderer + (0x26 * sizeof(uint32_t))), sizeof(void*)))
                {
                    auto device = *(IDirect3DDevice9**)(renderer + (0x26 * sizeof(uint32_t)));
                    if (device && !IsBadReadPtr(device, sizeof(void*)))
                    {
                        viewportResult = device->GetViewport(&viewport);
                        scissorResult = device->GetScissorRect(&scissor);
                        scissorStateResult = device->GetRenderState(
                            D3DRS_SCISSORTESTENABLE, &scissorEnabled);
                    }
                }

                spd::log()->info(
                    "[SUBTITLE-ACTIVE] calls={} this=0x{:08X} controller=0x{:08X} child={} a2=0x{:08X} "
                    "viewportHr=0x{:08X} viewport=({}, {}, {}x{}) "
                    "scissorHr=0x{:08X} scissor=({}, {})-({}, {}) "
                    "scissorStateHr=0x{:08X} enabled={}",
                    callCount, (uint32_t)_this, (uint32_t)subtitleController,
                    subtitleController != (uintptr_t)_this, (uint32_t)a2,
                    (uint32_t)viewportResult, viewport.X, viewport.Y, viewport.Width, viewport.Height,
                    (uint32_t)scissorResult, scissor.left, scissor.top, scissor.right, scissor.bottom,
                    (uint32_t)scissorStateResult, scissorEnabled);
            }
        })

        if (splitScreenActive && bSubtitlePerPlayer &&
            IsTextVoiceController(subtitleController))
        {
            RenderTextVoiceForBothViewports(_this, a2);
            return;
        }

        if (subtitleViewportSide != SubtitleViewportSide::Automatic)
        {
            RenderSubtitleAtSplitViewport(
                _this, a2, subtitleViewportSide, false);
            return;
        }

        return sub_E18040(_this, SUBTITLES, a2);
    }

    return sub_E18040(_this, RESCALE, a2);
}

void __fastcall sub_E18040_action_icon2(int _this, int edx, int a2)
{
    // Keep the original SP transform path. Only true split screen bypasses
    // FusionFix's generic HUD rescale, whose 0.8 X scale and +0.25 H offset
    // made this fixed prompt too small, too far left and partly off-screen.
    if (!IsSplitScreenActive())
        return sub_E18040_rescale(_this, edx, a2);

    return sub_E18040(_this, edx, a2);
}

static bool IsActiveDualMonitorFileText(uintptr_t object,
    uint32_t physicalWidth, uint32_t physicalHeight)
{
    constexpr uintptr_t guiStateFlagsOffset = 0x148;
    if (!object || IsBadReadPtr(reinterpret_cast<void*>(object),
            guiStateFlagsOffset + sizeof(uint32_t)))
    {
        return false;
    }

    return rev2coop::ShouldReplayFileText(
        *reinterpret_cast<uint32_t*>(object),
        *reinterpret_cast<uint32_t*>(object + guiStateFlagsOffset),
        bDualMonitorMode, IsSplitScreenActive(), physicalWidth, physicalHeight);
}

void __fastcall sub_E18040_file_text(int _this, int edx, int a2)
{
    constexpr uintptr_t localXOffset = 0x40;
    const auto object = static_cast<uintptr_t>(_this);
    uint32_t physicalWidth = 0;
    uint32_t physicalHeight = 0;

    if (gDualFileTextReplayActive ||
        !GetPhysicalRendererSize(physicalWidth, physicalHeight) ||
        !IsActiveDualMonitorFileText(object, physicalWidth, physicalHeight))
    {
        return sub_E18040_rescale(_this, edx, a2);
    }

    // Match the confirmed live ordering exactly: remember the source X before
    // the normal left draw, replay at physicalWidth/2, then restore the source
    // controller synchronously. Cached/inactive FileText instances never enter
    // this path, and non-split SP is already mirrored at Present.
    auto& localX = *reinterpret_cast<float*>(object + localXOffset);
    const rev2coop::FileTextReplayPosition position{localX, physicalWidth};
    sub_E18040_rescale(_this, edx, a2);

    gDualFileTextReplayActive = true;
    localX = position.ReplayX();
    sub_E18040_rescale(_this, edx, a2);
    position.Restore(localX);
    gDualFileTextReplayActive = false;
}

static bool InstallDualMonitorFileText()
{
    constexpr uintptr_t nativeRescaleEntry = 0x00E18040;
    if (*reinterpret_cast<uintptr_t*>(uGUIFileText) != nativeRescaleEntry)
        return false;

    injector::WriteMemory(uGUIFileText, sub_E18040_file_text, true);
    return true;
}

// All three duplicated pause elements are native full-canvas GUI controllers.
// The checks below deliberately identify their *semantic* pause relationship,
// rather than retaining any heap address discovered during a live session.
static bool IsActiveFullCanvasGui(uintptr_t object, uintptr_t drawSlot)
{
    constexpr uintptr_t drawSlotFromVtable = 0x58;
    constexpr uintptr_t guiRootOffset = 0xF4;
    constexpr uintptr_t rootOwnerOffset = 0x6C;
    constexpr uintptr_t guiStateFlagsOffset = 0x148;
    constexpr uintptr_t cachedBoundsOffset = 0x168;
    constexpr uint32_t enabledAndVisibleMask = 0x201;

    if (!object || drawSlot < drawSlotFromVtable ||
        IsBadReadPtr(reinterpret_cast<void*>(object), cachedBoundsOffset + 16))
    {
        return false;
    }

    const auto expectedVtable = drawSlot - drawSlotFromVtable;
    if (*reinterpret_cast<uintptr_t*>(object) != expectedVtable)
        return false;

    const auto root = *reinterpret_cast<uintptr_t*>(object + guiRootOffset);
    if (!root || IsBadReadPtr(
            reinterpret_cast<void*>(root + rootOwnerOffset), sizeof(uintptr_t)) ||
        *reinterpret_cast<uintptr_t*>(root + rootOwnerOffset) != object)
    {
        return false;
    }

    if ((*reinterpret_cast<uint32_t*>(object + guiStateFlagsOffset) &
         enabledAndVisibleMask) != enabledAndVisibleMask)
    {
        return false;
    }

    const auto* bounds = reinterpret_cast<const int32_t*>(object + cachedBoundsOffset);
    const bool canonicalBounds = bounds[0] == 0 && bounds[1] == 0 &&
        bounds[2] == GetResX() && bounds[3] == GetResY();
    if (canonicalBounds)
        return true;

    // The translated replay can update the controller's cached bounds even
    // though its source position remains untouched. Accept that exact dynamic
    // cache as well, otherwise the right copy is rejected on the next frame
    // and the pause menu visibly renders only every other frame.
    const auto splitWidth = GetCurrentSplitScreenResX();
    return bDualMonitorMode && IsSplitScreenActive() && splitWidth > 0 &&
        bounds[0] == splitWidth && bounds[1] == 0 &&
        bounds[2] == splitWidth + GetResX() && bounds[3] == GetResY();
}

static bool IsPauseCommonMenu(uintptr_t object)
{
    return IsActiveFullCanvasGui(object, uGUICommonMenu);
}

static bool IsPausePurpose(uintptr_t object)
{
    constexpr uintptr_t previousControllerOffset = 0x18;
    if (!IsActiveFullCanvasGui(object, uGUIPurpose) ||
        IsBadReadPtr(reinterpret_cast<void*>(object + previousControllerOffset),
            sizeof(uintptr_t)))
    {
        return false;
    }

    return IsPauseCommonMenu(
        *reinterpret_cast<uintptr_t*>(object + previousControllerOffset));
}

static uintptr_t GetActivePauseCommonMenu()
{
    return static_cast<uintptr_t>(
        InterlockedCompareExchange(&gActivePauseCommonMenu, 0, 0));
}

static bool IsDualMonitorPauseReplayActive()
{
    return bDualMonitorMode && IsSplitScreenActive() && GetResX() > 0 &&
        GetCurrentSplitScreenResX() > 0;
}

static float GetDualMonitorPassTranslationXNdc()
{
    // NDC spans two units horizontally. This remains correct for every
    // equal-width two-monitor canvas (including fake presenter resolutions).
    return 2.0f * static_cast<float>(GetCurrentSplitScreenResX()) /
        static_cast<float>(GetResX());
}

static void RenderPauseGuiForDualMonitors(int object, int edx, int a2)
{
    sub_E18040_rescale(object, edx, a2);
    if (!IsDualMonitorPauseReplayActive())
        return;

    constexpr uintptr_t cachedBoundsOffset = 0x168;
    auto* cachedBounds = reinterpret_cast<int32_t*>(
        static_cast<uintptr_t>(object) + cachedBoundsOffset);
    const std::array<int32_t, 4> originalCachedBounds = {
        cachedBounds[0], cachedBounds[1], cachedBounds[2], cachedBounds[3]
    };

    const auto originalTranslation = gDualGuiPassTranslationXNdc;
    gDualGuiPassTranslationXNdc = originalTranslation +
        GetDualMonitorPassTranslationXNdc();
    sub_E18040_rescale(object, edx, a2);
    gDualGuiPassTranslationXNdc = originalTranslation;

    // sub_E18040 queues its transform but also leaves the translated bounds
    // in the shared controller cache. Restore the left/native cache
    // immediately so layout tests and the next frame see canonical state.
    std::copy(originalCachedBounds.begin(), originalCachedBounds.end(), cachedBounds);
}

void __fastcall sub_E18040_pause_common_menu(int _this, int edx, int a2)
{
    const auto object = static_cast<uintptr_t>(_this);
    if (!IsPauseCommonMenu(object))
    {
        if (GetActivePauseCommonMenu() == object)
            InterlockedExchange(&gActivePauseCommonMenu, 0);
        return sub_E18040_rescale(_this, edx, a2);
    }

    InterlockedExchange(&gActivePauseCommonMenu, static_cast<LONG>(object));
    return RenderPauseGuiForDualMonitors(_this, edx, a2);
}

void __fastcall sub_E18040_pause_purpose(int _this, int edx, int a2)
{
    if (!IsPausePurpose(static_cast<uintptr_t>(_this)))
        return sub_E18040_rescale(_this, edx, a2);

    return RenderPauseGuiForDualMonitors(_this, edx, a2);
}

void __fastcall sub_E18040_pause_guide(int _this, int edx, int a2)
{
    const auto object = static_cast<uintptr_t>(_this);
    if (!IsActiveFullCanvasGui(object, uGUIGuide) ||
        !IsPauseCommonMenu(GetActivePauseCommonMenu()))
    {
        return sub_E18040_rescale(_this, edx, a2);
    }

    return RenderPauseGuiForDualMonitors(_this, edx, a2);
}

static bool InstallDualMonitorPauseGui()
{
    constexpr uintptr_t nativeRescaleEntry = 0x00E18040;
    constexpr uintptr_t drawSlots[] = { uGUICommonMenu, uGUIPurpose, uGUIGuide };
    for (const auto drawSlot : drawSlots)
    {
        if (*reinterpret_cast<uintptr_t*>(drawSlot) != nativeRescaleEntry)
            return false;
    }

    injector::WriteMemory(uGUICommonMenu, sub_E18040_pause_common_menu, true);
    injector::WriteMemory(uGUIPurpose, sub_E18040_pause_purpose, true);
    injector::WriteMemory(uGUIGuide, sub_E18040_pause_guide, true);
    return true;
}

static bool InstallFixedHudActionPrompt()
{
    constexpr uintptr_t layoutTestAddress = 0x0088F944;
    constexpr uint8_t expectedLayoutTest[] = { 0x84, 0xC0 }; // TEST AL, AL
    constexpr uintptr_t nativeRescaleEntry = 0x00E18040;

    if (std::memcmp(reinterpret_cast<const void*>(layoutTestAddress),
            expectedLayoutTest, sizeof(expectedLayoutTest)) != 0 ||
        *reinterpret_cast<uintptr_t*>(uGUIActionIcon2) != nativeRescaleEntry)
    {
        return false;
    }

    // 30 C0 is XOR AL,AL: select this controller's native SP-local layout.
    // Change only the first byte so the original two-byte instruction length
    // and all following branch addresses remain unchanged.
    injector::WriteMemory<uint8_t>(layoutTestAddress, 0x30, true);
    injector::WriteMemory(uGUIActionIcon2, sub_E18040_action_icon2, true);
    return true;
}

void __fastcall sub_E18040_stretch(int _this, int edx, int a2)
{
    return sub_E18040(_this, STRETCH, a2);
}

void __fastcall sub_E18040_fade(int _this, int edx, int a2)
{
    return sub_E18040(_this, FADE_STRETCH, a2);
}

void __fastcall sub_E18040_offset(int _this, int edx, int a2)
{
    return sub_E18040(_this, OFFSET, a2);
}

void __fastcall sub_B82960(void* _this, void* edx, float a2, float a3, float a4, float a5)
{
    a4 *= fFOVFactor;
    a2 /= fFOVFactor;
    a2 /= GetDiff();
    return injector::fastcall<void(void*, void*, float, float, float, float)>::call(0xB82960, _this, edx, a2, a3, a4, a5);
}

//IDirect3DVertexShader9* shader_4F0EE939 = nullptr;
IDirect3DVertexShader9* __stdcall CreateVertexShaderHook(const DWORD** a1)
{
    if (!a1)
        return nullptr;

    auto pDevice = (IDirect3DDevice9*)*((uint32_t*)*(uint32_t*)0x15E0388 + 0x26);

    IDirect3DVertexShader9* pShader = nullptr;
    pDevice->CreateVertexShader(a1[2], &pShader);

    if (pShader != nullptr)
    {
        static std::vector<uint8_t> pbFunc;
        UINT len;
        pShader->GetFunction(nullptr, &len);
        if (pbFunc.size() < len)
            pbFunc.resize(len);

        pShader->GetFunction(pbFunc.data(), &len);

        auto crc = crc32(0, pbFunc.data(), len);

        // various overlays (low health, waiting for partner, pause text, maybe more)
        if (crc == 0x4F0EE939)
        {
            const char* shader_text =
                "vs_3_0\n"
                "def c0, 32768, -128, 0.00390625, 0.25\n"
                "def c4, 1, 0, -128, 4\n"
                "def c5, 0.000244140654, 0.5, 6.28318548, -3.14159274\n"
                "def c6, 2, -1, 1, 9.99999997e-007\n"
                "def c7, 1.8, 0.28125, 0, 0\n" // 1.8 instead of 1.6 to cover the gaps in ultra wide
                "dcl_position v0\n"
                "dcl_normal v1\n"
                "dcl_tangent v2\n"
                "dcl_binormal v3\n"
                "dcl_texcoord v4\n"
                "dcl_position o0\n"
                "dcl_texcoord o1\n"
                "dcl_texcoord1 o2\n"
                "mov r0.x, v3.x\n"
                "add o0.z, r0.x, v0.z\n"
                "add r0.xyz, c0.x, v3.zwyw\n"
                "mul r0.xz, r0, c0.z\n"
                "mad r0.y, r0.y, c5.x, c5.y\n"
                "frc r0.y, r0.y\n"
                "mad r0.y, r0.y, c5.z, c5.w\n"
                "sincos r1.xy, r0.y\n"
                "mul o1.xyz, r0.z, v1\n"
                "mul o2.xy, c3, v2\n"
                "add r0.yz, c0.y, v4.xxyw\n"
                "mul r0.xy, r0.x, r0.yzzw\n"
                "mad r0.zw, v4.z, c4.xyxy, c4\n"
                "mul r0.xy, r0.zwzw, r0\n"
                "mul r0.x, r0.x, c0.w\n"
                "mul r0.yz, r1.xyxw, r0.y\n"
                "mad r2.x, r0.x, r1.x, -r0.y\n"
                "mad r2.y, r0.x, r1.y, r0.z\n"
                "mov r0.xy, v0\n"
                "mul r0.xy, r0, c2\n"
                "mad r0.xy, r0, c6.x, c6.yzzw\n"
                "slt r0.z, v1.w, c6.w\n"
                "add r0.z, -r0.z, c4.x\n"
                "rcp r10.x, c2.x\n"
                "mul r10.x, c2.w, r10.x\n"
                "mul r10.x, r10.x, c7.y\n"
                "mul r0.x, r0.x, r10.x\n"
                "mul o0.x, r0.x, c7.x\n"
                "mad o0.y, c1.y, r0.z, r0.y\n"
                "mov o0.w, r0.z\n"
                "mov o1.w, v1.w\n"
                "mov o2.zw, c4.y\n";

            LPD3DXBUFFER pCode;
            LPD3DXBUFFER pErrorMsgs;
            LPDWORD pShaderData;
            auto result = D3DXAssembleShader(shader_text, strlen(shader_text), NULL, NULL, 0, &pCode, &pErrorMsgs);
            if (SUCCEEDED(result))
            {
                pShaderData = (DWORD*)pCode->GetBufferPointer();
                IDirect3DVertexShader9* shader = nullptr;
                if (pDevice->CreateVertexShader(pShaderData, &shader) == D3D_OK)
                {
                    pShader->Release();
                    return shader;
                }
            }
        }
        else if (crc == 0x1287841D)
        {
            g_screenVertexShader = pShader;

            // inject additional, alternative screenspace shader for FMV fixups
            constexpr auto src = R"(
            struct VS_INPUT {
                float4 position : POSITION;
            };
            
            struct VS_OUTPUT {
                float4 position : POSITION;
                float4 uv : TEXCOORD;
            };
            
            float2 fScreenHalfPixelOffset : register(c1);
            float fHorizontalAspectScale : register(c20);
            float fHorizontalOffset : register(c21);
            
            VS_OUTPUT main(VS_INPUT input)
            {
                VS_OUTPUT output;
            
                output.position = float4(
                  -fScreenHalfPixelOffset.x + input.position.x * fHorizontalAspectScale + fHorizontalOffset,
                  fScreenHalfPixelOffset.y + input.position.y,
                  0.0,
                  1.0);
                output.uv = float4(
                  1.0 * input.position.z,
                  1.0 * input.position.w,
                  0.0, 0.0
                );
            
                return output;
            })";

            LPD3DXBUFFER code;
            if (SUCCEEDED(D3DXCompileShader(src, strlen(src), nullptr, nullptr, "main", "vs_3_0", NULL, &code, nullptr, nullptr)))
            {
                pDevice->CreateVertexShader(reinterpret_cast<const DWORD*>(code->GetBufferPointer()), &g_myScreenVertexShader);
            }
        }
    }

    return pShader;
}

IDirect3DPixelShader9* __stdcall CreatePixelShaderHook(const DWORD** a1)
{
    if (!a1)
        return nullptr;

    auto pDevice = (IDirect3DDevice9*)*((uint32_t*)*(uint32_t*)0x15E0388 + 0x26);

    IDirect3DPixelShader9* pShader = nullptr;
    pDevice->CreatePixelShader(a1[2], &pShader);

    if (pShader != nullptr)
    {
        UINT len;
        pShader->GetFunction(nullptr, &len);
        std::vector<uint8_t> pbFunc(len, 0);

        pShader->GetFunction(pbFunc.data(), &len);

        auto crc = crc32(0, pbFunc.data(), len);

        if (crc == 0x9D190FC7)
        {
            g_wmvYuvDecodePixelShader = pShader;
        }
    }

    return pShader;
}

void __stdcall SplitScreenSetupTop(void* a1, int32_t* a2)
{
    a2[0] = 0;                                         // X start
    a2[1] = 0;                                         // Y start
    a2[2] = (int32_t)(720.0f * GetAspectRatio() / 2.0f); // X end (half width)
    a2[3] = (int32_t)(720.0f);                         // Y end (full height)
    return injector::stdcall<void(void*, int32_t*)>::call(0x4AC310, a1, a2);
}

void __stdcall SplitScreenSetupBottom(void* a1, int32_t* a2)
{
    a2[0] = (int32_t)(720.0f * GetAspectRatio() / 2.0f); // X start (half width start)
    a2[1] = 0;                                           // Y start
    a2[2] = (int32_t)(720.0f * GetAspectRatio());         // X end (full width)
    a2[3] = (int32_t)(720.0f);                           // Y end (full height)
    return injector::stdcall<void(void*, int32_t*)>::call(0x4AC310, a1, a2);
}

namespace dualmonitor
{
    enum class InstallAttempt
    {
        NotReady,
        Installed,
        PermanentFailure
    };

    constexpr uintptr_t GraphicsPointer = 0x015DE88C;
    constexpr uintptr_t RendererPointer = 0x015E0388;
    constexpr uintptr_t SplitControllerPointer = 0x0157AE00;
    constexpr uintptr_t UpdateLayoutAddress = 0x004AE570;
    constexpr uintptr_t NativeRectConverterAddress = 0x004AC310;
    constexpr uintptr_t NativeRectConverterCall = 0x004AE831;
    constexpr uintptr_t Screen0CameraOffset = 0x34;
    constexpr uintptr_t Screen0RectOffset = 0x48;
    constexpr uintptr_t Screen1FallbackRectOffset = 0x1D8;
    constexpr uintptr_t CachedModeOffset = 0xCE0;
    constexpr uintptr_t LayoutDirtyOffset = 0xD0C;
    constexpr uintptr_t ActiveRectOffset = 0xD20;
    constexpr uintptr_t RendererWidthOffset = 0xB8;
    constexpr uintptr_t RendererHeightOffset = 0xBC;
    constexpr uintptr_t SplitModeOffset = 0x8F4;
    constexpr uintptr_t NormalCameraVtable = 0x01264F30;
    constexpr uintptr_t EventMotionCameraVtable = 0x01264FE0;
    constexpr UINT BackbufferValidationInterval = 300;

    struct RuntimeState
    {
        IDirect3DDevice9* device = nullptr;
        IDirect3DSurface9* backbuffer = nullptr;
        IDirect3DSurface9* intermediate = nullptr;
        UINT width = 0;
        UINT height = 0;
        D3DFORMAT format = D3DFMT_UNKNOWN;
        UINT validationCountdown = 0;
        bool layoutInitialized = false;
        bool initialLayoutPending = true;
        bool previousSplit = false;
        bool dualWasEnabled = false;
    };

    static RuntimeState gState;
    static volatile LONG gInstallRequested = 0;
    static volatile LONG gInstallFinished = 0;
    static volatile LONG gInstallBusy = 0;
    static ULONGLONG gNextInstallAttempt = 0;

    static uint8_t* GetGraphics()
    {
        return reinterpret_cast<uint8_t*>(
            *reinterpret_cast<uintptr_t*>(GraphicsPointer));
    }

    static uint8_t* GetRenderer()
    {
        return reinterpret_cast<uint8_t*>(
            *reinterpret_cast<uintptr_t*>(RendererPointer));
    }

    static uint8_t* GetSplitController()
    {
        return reinterpret_cast<uint8_t*>(
            *reinterpret_cast<uintptr_t*>(SplitControllerPointer));
    }

    static RECT ReadRect(uint8_t* address)
    {
        return *reinterpret_cast<RECT*>(address);
    }

    static void WriteRect(uint8_t* address, LONG left, LONG top,
        LONG right, LONG bottom)
    {
        *reinterpret_cast<RECT*>(address) = { left, top, right, bottom };
    }

    static bool IsRect(uint8_t* address, LONG left, LONG top,
        LONG right, LONG bottom)
    {
        const auto rect = ReadRect(address);
        return rect.left == left && rect.top == top &&
            rect.right == right && rect.bottom == bottom;
    }

    static void ReleaseSurfaces()
    {
        if (gState.intermediate)
        {
            gState.intermediate->Release();
            gState.intermediate = nullptr;
        }
        if (gState.backbuffer)
        {
            gState.backbuffer->Release();
            gState.backbuffer = nullptr;
        }
    }

    static bool RefreshBackbuffer(bool force)
    {
        if (!gState.device || (!force && gState.backbuffer))
            return gState.backbuffer != nullptr;

        IDirect3DSurface9* current = nullptr;
        if (FAILED(gState.device->GetBackBuffer(
                0, 0, D3DBACKBUFFER_TYPE_MONO, &current)) || !current)
        {
            return false;
        }

        if (current == gState.backbuffer)
        {
            // GetBackBuffer returned an additional COM reference.
            current->Release();
            gState.validationCountdown = BackbufferValidationInterval;
            return true;
        }

        D3DSURFACE_DESC description = {};
        if (FAILED(current->GetDesc(&description)) ||
            description.Width < 2 || (description.Width & 1) != 0 ||
            description.Height == 0)
        {
            current->Release();
            return false;
        }

        ReleaseSurfaces();
        gState.backbuffer = current;
        gState.width = description.Width;
        gState.height = description.Height;
        gState.format = description.Format;
        gState.layoutInitialized = false;
        gState.initialLayoutPending = true;
        gState.validationCountdown = BackbufferValidationInterval;
        return true;
    }

    static bool EnsureIntermediate()
    {
        if (gState.intermediate)
            return true;

        return SUCCEEDED(gState.device->CreateRenderTarget(
            gState.width / 2, gState.height, gState.format,
            D3DMULTISAMPLE_NONE, 0, FALSE, &gState.intermediate, nullptr)) &&
            gState.intermediate != nullptr;
    }

    static void RestoreFullLogicalCaches()
    {
        auto renderer = GetRenderer();
        if (!renderer || !gState.width || !gState.height)
            return;

        *reinterpret_cast<uint32_t*>(renderer + RendererWidthOffset) = gState.width;
        *reinterpret_cast<uint32_t*>(renderer + RendererHeightOffset) = gState.height;
        ResX = static_cast<int32_t>(gState.width);
        ResY = static_cast<int32_t>(gState.height);
    }

    static void ApplyHalfLogicalState()
    {
        auto renderer = GetRenderer();
        auto graphics = GetGraphics();
        if (!renderer || !graphics || !gState.width || !gState.height)
            return;

        // The physical renderer and all render targets remain full-size.
        // Only FusionFix's logical GUI/input width and the native fallback
        // screen record describe one equal monitor.
        *reinterpret_cast<uint32_t*>(renderer + RendererWidthOffset) = gState.width;
        *reinterpret_cast<uint32_t*>(renderer + RendererHeightOffset) = gState.height;
        ResX = static_cast<int32_t>(gState.width / 2);
        ResY = static_cast<int32_t>(gState.height);
        WriteRect(graphics + Screen1FallbackRectOffset,
            0, 0, static_cast<LONG>(gState.width / 2),
            static_cast<LONG>(gState.height));
    }

    static void RebuildCurrentNativeLayout()
    {
        auto graphics = GetGraphics();
        if (!graphics)
            return;

        *reinterpret_cast<uint8_t*>(graphics + LayoutDirtyOffset) = 1;
        reinterpret_cast<void(__thiscall*)(void*)>(
            UpdateLayoutAddress)(graphics);
    }

    static uintptr_t GetScreen0PreservableCamera(
        uint8_t* graphics, uint32_t originalMode)
    {
        if (!graphics || IsBadReadPtr(
                graphics + Screen0CameraOffset, sizeof(uintptr_t)))
        {
            return 0;
        }

        const auto camera = *reinterpret_cast<uintptr_t*>(
            graphics + Screen0CameraOffset);
        if (!camera || IsBadReadPtr(
                reinterpret_cast<void*>(camera), sizeof(uintptr_t)))
        {
            return 0;
        }

        const auto cameraVtable = *reinterpret_cast<uintptr_t*>(camera);
        const bool eventCamera = cameraVtable == EventMotionCameraVtable;
        // Mode 0 is the game's short single-view transition. Unlike the long
        // scripted cutscene path, it reuses the normal camera belonging to the
        // character selected by the event (Claire or Moira). Preserve that
        // native choice rather than rebuilding screen 0 from camera mapping 0.
        const bool selectedGameplayCamera = originalMode == 0 &&
            cameraVtable == NormalCameraVtable;
        return eventCamera || selectedGameplayCamera ? camera : 0;
    }

    static bool ApplyNativeLeftLayout()
    {
        auto controller = GetSplitController();
        auto renderer = GetRenderer();
        auto graphics = GetGraphics();
        if (!controller || !renderer || !graphics ||
            *reinterpret_cast<uint32_t*>(controller + SplitModeOffset) == 1)
        {
            return false;
        }

        auto& mode = *reinterpret_cast<uint32_t*>(controller + SplitModeOffset);
        auto& rendererWidth =
            *reinterpret_cast<uint32_t*>(renderer + RendererWidthOffset);
        auto& rendererHeight =
            *reinterpret_cast<uint32_t*>(renderer + RendererHeightOffset);
        const auto originalMode = mode;
        const auto originalRendererWidth = rendererWidth;
        const auto originalRendererHeight = rendererHeight;
        const auto preservedCamera =
            GetScreen0PreservableCamera(graphics, originalMode);

        // Mode 2 is the game's native single-view constructor. Expose W/2 x H
        // only for this synchronous rebuild, then immediately restore the
        // physical renderer dimensions and the manager's real mode.
        mode = 2;
        rendererWidth = gState.width / 2;
        rendererHeight = gState.height;
        RebuildCurrentNativeLayout();

        // Preserve the camera already selected by the game across only our
        // synchronous W/2 rebuild. Long scripted scenes install an exact
        // uEventMotionCamera; short mode-0 scenes install the exact normal
        // camera of the interacting character. Without the second case a
        // Moira event is silently rebound to camera mapping 0 (Claire).
        if (preservedCamera && !IsBadReadPtr(
                reinterpret_cast<void*>(preservedCamera), sizeof(uintptr_t)))
        {
            const auto preservedVtable =
                *reinterpret_cast<uintptr_t*>(preservedCamera);
            const bool stillValid =
                preservedVtable == EventMotionCameraVtable ||
                (originalMode == 0 && preservedVtable == NormalCameraVtable);
            if (stillValid)
            {
                *reinterpret_cast<uintptr_t*>(
                    graphics + Screen0CameraOffset) = preservedCamera;
            }
        }

        ApplyHalfLogicalState();
        rendererWidth = originalRendererWidth;
        rendererHeight = originalRendererHeight;
        mode = originalMode;

        // updateLayout cached temporary mode 2. Acknowledge the real mode so
        // the game's next per-frame update does not undo the native W/2 rect.
        *reinterpret_cast<uint32_t*>(graphics + CachedModeOffset) = originalMode;
        return true;
    }

    static void RestorePhysicalLayout()
    {
        auto graphics = GetGraphics();
        if (!graphics || !gState.width || !gState.height)
            return;

        RestoreFullLogicalCaches();
        WriteRect(graphics + Screen1FallbackRectOffset,
            0, 0, static_cast<LONG>(gState.width),
            static_cast<LONG>(gState.height));
        RebuildCurrentNativeLayout();
        gState.layoutInitialized = false;
        gState.initialLayoutPending = true;
        gState.previousSplit = false;
    }

    static void InitializeLayoutState()
    {
        if (!gState.width || !gState.height || !GetGraphics() || !GetRenderer())
            return;

        RestoreFullLogicalCaches();
        gState.layoutInitialized = true;
        gState.initialLayoutPending = true;
        // Treat an already active split as a transition so native screen 0/1
        // ownership is rebuilt once after startup or a device reset.
        gState.previousSplit = false;
    }

    static void MirrorLeftToBoth()
    {
        if (!gState.backbuffer || !EnsureIntermediate())
            return;

        const RECT source = {
            0, 0, static_cast<LONG>(gState.width / 2),
            static_cast<LONG>(gState.height)
        };
        const RECT left = source;
        const RECT right = {
            static_cast<LONG>(gState.width / 2), 0,
            static_cast<LONG>(gState.width), static_cast<LONG>(gState.height)
        };

        HRESULT result = gState.device->StretchRect(
            gState.backbuffer, &source, gState.intermediate, nullptr, D3DTEXF_NONE);
        if (SUCCEEDED(result))
            result = gState.device->StretchRect(
                gState.intermediate, nullptr, gState.backbuffer, &left, D3DTEXF_NONE);
        if (SUCCEEDED(result))
            result = gState.device->StretchRect(
                gState.intermediate, nullptr, gState.backbuffer, &right, D3DTEXF_NONE);

        if (FAILED(result))
        {
            // Retry lazily with fresh surfaces. No per-frame GetBackBuffer is
            // needed during normal rendering.
            ReleaseSurfaces();
            gState.layoutInitialized = false;
        }
    }

    static void HandlePresent()
    {
        InterlockedIncrement(&gDualMonitorPresentSerial);

        if (!bDualMonitorMode)
        {
            if (gState.dualWasEnabled && gState.layoutInitialized)
                RestorePhysicalLayout();
            gState.dualWasEnabled = false;
            return;
        }
        gState.dualWasEnabled = true;

        const bool splitBeforeRefresh = IsSplitScreenActive();
        const bool enteringNonSplit = gState.previousSplit && !splitBeforeRefresh;
        bool validateBackbuffer = !gState.backbuffer || enteringNonSplit;
        if (!splitBeforeRefresh && !validateBackbuffer)
        {
            if (gState.validationCountdown == 0)
                validateBackbuffer = true;
            else
                --gState.validationCountdown;
        }
        if (validateBackbuffer && !RefreshBackbuffer(true))
            return;

        if (!gState.layoutInitialized)
            InitializeLayoutState();
        if (!gState.layoutInitialized)
            return;

        const bool split = IsSplitScreenActive();
        const bool enteredSplit = !gState.previousSplit && split;
        if (gState.previousSplit && !split)
            gState.initialLayoutPending = true;
        gState.previousSplit = split;

        auto graphics = GetGraphics();
        if (!graphics)
            return;

        if (split)
        {
            // Logical caches may be restored every frame. Screen slots remain
            // exclusively owned by the native co-op layout after this edge.
            RestoreFullLogicalCaches();
            if (enteredSplit)
            {
                WriteRect(graphics + Screen1FallbackRectOffset,
                    0, 0, static_cast<LONG>(gState.width),
                    static_cast<LONG>(gState.height));
                RebuildCurrentNativeLayout();
            }
            return;
        }

        ApplyHalfLogicalState();
        if (gState.initialLayoutPending)
        {
            gState.initialLayoutPending = false;
            ApplyNativeLeftLayout();
            return;
        }

        if (!IsRect(graphics + Screen0RectOffset, 0, 0,
                static_cast<LONG>(gState.width / 2),
                static_cast<LONG>(gState.height)))
        {
            ApplyNativeLeftLayout();
            return;
        }

        MirrorLeftToBoth();
    }

    static HRESULT __stdcall ResetHook(IDirect3DDevice9* device,
        D3DPRESENT_PARAMETERS* parameters)
    {
        if (device == gState.device)
        {
            // Both retained surfaces are invalid across Reset; reacquire them
            // lazily from the new swap chain on the next Present.
            ReleaseSurfaces();
            gState.layoutInitialized = false;
            gState.initialLayoutPending = true;
            gState.previousSplit = false;
        }
        return gDualMonitorResetHook.unsafe_stdcall<HRESULT>(device, parameters);
    }

    static HRESULT __stdcall PresentHook(IDirect3DDevice9* device,
        const RECT* sourceRect, const RECT* destinationRect,
        HWND destinationWindow, const RGNDATA* dirtyRegion)
    {
        if (device == gState.device)
            HandlePresent();
        return gDualMonitorPresentHook.unsafe_stdcall<HRESULT>(
            device, sourceRect, destinationRect, destinationWindow, dirtyRegion);
    }

    static void __stdcall SingleScreenRectConverter(void* owner, int32_t* rect)
    {
        auto graphics = GetGraphics();
        const bool target = bDualMonitorMode && gState.layoutInitialized &&
            !IsSplitScreenActive() && graphics && rect &&
            rect[0] == 0 && rect[1] == 0 && rect[2] == 1280 && rect[3] == 720;
        RECT originalActiveRect = {};
        if (target)
        {
            originalActiveRect = ReadRect(graphics + ActiveRectOffset);
            WriteRect(graphics + ActiveRectOffset, 0, 0,
                static_cast<LONG>(gState.width / 2),
                static_cast<LONG>(gState.height));
        }

        reinterpret_cast<void(__stdcall*)(void*, int32_t*)>(
            NativeRectConverterAddress)(owner, rect);

        if (target)
            *reinterpret_cast<RECT*>(graphics + ActiveRectOffset) = originalActiveRect;
    }

    static InstallAttempt TryInstall()
    {
        auto renderer = GetRenderer();
        if (!renderer)
            return InstallAttempt::NotReady;
        gState.device = *reinterpret_cast<IDirect3DDevice9**>(renderer + 0x98);
        if (!gState.device)
            return InstallAttempt::NotReady;

        const auto callTarget = NativeRectConverterCall + 5 +
            *reinterpret_cast<int32_t*>(NativeRectConverterCall + 1);
        if (*reinterpret_cast<uint8_t*>(NativeRectConverterCall) != 0xE8 ||
            callTarget != NativeRectConverterAddress)
        {
            return InstallAttempt::PermanentFailure;
        }

        auto** vtable = *reinterpret_cast<void***>(gState.device);
        if (!vtable)
            return InstallAttempt::NotReady;
        gDualMonitorResetHook = safetyhook::create_inline(vtable[16], ResetHook);
        gDualMonitorPresentHook = safetyhook::create_inline(vtable[17], PresentHook);
        if (!gDualMonitorResetHook || !gDualMonitorPresentHook)
        {
            gDualMonitorPresentHook = {};
            gDualMonitorResetHook = {};
            return InstallAttempt::PermanentFailure;
        }

        injector::MakeCALL(NativeRectConverterCall,
            SingleScreenRectConverter, true);
        return InstallAttempt::Installed;
    }

    static void RequestInstall()
    {
        InterlockedExchange(&gInstallRequested, 1);
    }

    void PollInstall()
    {
        if (!bDualMonitorMode ||
            !InterlockedCompareExchange(&gInstallRequested, 0, 0) ||
            InterlockedCompareExchange(&gInstallFinished, 0, 0))
        {
            return;
        }

        const auto now = GetTickCount64();
        if (now < gNextInstallAttempt ||
            InterlockedCompareExchange(&gInstallBusy, 1, 0) != 0)
        {
            return;
        }
        gNextInstallAttempt = now + 100;

        const auto result = TryInstall();
        if (result == InstallAttempt::Installed)
        {
            InterlockedExchange(&gInstallFinished, 1);
            rev2coop::Report(
                "[DUAL] Native W/2 single-view layout, FMV and final-frame mirroring enabled");
        }
        else if (result == InstallAttempt::PermanentFailure)
        {
            InterlockedExchange(&gInstallFinished, -1);
            rev2coop::Report(
                "[DUAL] Non-split renderer skipped: native/D3D hook guard failed");
        }

        InterlockedExchange(&gInstallBusy, 0);
    }
}

bool bDisableCreateQuery = false;
void __fastcall gpuCommandBufferSync(IDirect3DDevice9** m_ppD3DDevice, void* edx)
{
    if (bDisableCreateQuery)
        return;

    IDirect3DQuery9* pEventQuery = NULL;
    m_ppD3DDevice[38]->CreateQuery(D3DQUERYTYPE_EVENT, &pEventQuery);

    if (pEventQuery)
    {
        pEventQuery->Issue(D3DISSUE_END);
        while (pEventQuery->GetData(NULL, 0, D3DGETDATA_FLUSH) == S_FALSE)
            Sleep(0);
        pEventQuery->Release();
    }
}

bool bNeedsAutoclick = false;
injector::hook_back<const char* (__fastcall*)(void*, void*, int, int)> hb_954B40;
const char* __fastcall sub_954B40(void* _this, void* a2, int a3, int a4)
{
    static constexpr auto RestartStr = "Restart game from your last checkpoint.";
    static constexpr auto LoadSuccessful = "Load successful.";
    static constexpr auto ThisGameReq = "This game has an autosave feature.\r\nDo not turn off the power when the above icon is displayed.";

    auto ret = hb_954B40.fun(_this, a2, a3, a4);

    if (ret)
    {
        auto s = std::string_view(ret);

        if (s == RestartStr || s == LoadSuccessful || s == ThisGameReq)
        {
            bNeedsAutoclick = true;
        }
    }

    return ret;
}

std::future<void*> pXInputGetState;
injector::hook_back<DWORD(WINAPI*)(DWORD, XINPUT_STATE*)> hbXInputGetStateHook;
DWORD WINAPI XInputGetStateHook(DWORD dwUserIndex, XINPUT_STATE* pState)
{
    if (!hbXInputGetStateHook.fun)
        hbXInputGetStateHook.fun = (decltype(hbXInputGetStateHook.fun))pXInputGetState.get();

    auto ret = hbXInputGetStateHook.fun(dwUserIndex, pState);

    if (bNeedsAutoclick)
    {
        pState->Gamepad.wButtons = XINPUT_GAMEPAD_A;

        static auto frames = 0;
        if (frames % 10) {
            pState->Gamepad.wButtons = 0x0000;

            if (frames >= 2000) {
                frames = 0;
                bNeedsAutoclick = false;
            }
        }
        frames++;
    }

    return ret;
}

int nForceLogo = 0;
int sub_984240()
{
    return nForceLogo - 1;
}

static bool DisableCoopEffectExclusionFilter()
{
    // sBioEffect's updater writes mExclusionTrait=6 for split-screen and 0
    // otherwise. Change only that native MP contribution to 0 (the SP value).
    // Per-effect exclusion traits, resource checks, lifetime and view masks
    // remain untouched. Do not replace the global SP/MP predicate.
    constexpr uintptr_t checkAddress = 0xA85C6C;
    constexpr uint8_t expected[] = {
        0xA1, 0x8C, 0xE8, 0x5D, 0x01,             // mov eax,[15DE88C]
        0x33, 0xC9,                               // xor ecx,ecx
        0x83, 0xB8, 0xE0, 0x0C, 0x00, 0x00, 0x01, // cmp [eax+CE0],1
        0xBA, 0x06, 0x00, 0x00, 0x00,             // mov edx,6
        0x0F, 0x44, 0xCA,                         // cmove ecx,edx
        0x89, 0x8F, 0x28, 0x02, 0x00, 0x00        // mov [edi+228],ecx
    };
    if (std::memcmp(reinterpret_cast<const void*>(checkAddress),
                    expected, sizeof(expected)) != 0)
    {
        OutputDebugStringA("[GRAPHICS] Co-op effect filter patch skipped: unexpected code bytes\n");
        DBGONLY(spd::log()->warn(
            "[GRAPHICS] DisableCoopEffectFilter skipped: unexpected code bytes");)
        return false;
    }
    injector::WriteMemory<uint32_t>(checkAddress + 15, 0, true);
    DBGONLY(spd::log()->info(
        "[GRAPHICS] DisableCoopEffectFilter: native MP exclusion mask 6 -> 0");)
    return true;
}

static bool EnableCoopBulletMarkCreation()
{
    // sAdh::BulletMark creation (0xA7C390) exits when the cached split mode
    // at sRender+0xCE0 is 1. Bypass ONLY that exit, not the global game mode,
    // material checks, slot limit, resource lifetime or render routing.
    // Runtime appearance/stability is still unverified; opt-in INI test only.
    constexpr uintptr_t checkAddress = 0xA7C3B2;
    constexpr uint8_t expected[] = {
        0x83, 0xB8, 0xE0, 0x0C, 0x00, 0x00, 0x01, // cmp [eax+CE0],1
        0x0F, 0x84, 0x1D, 0x47, 0x00, 0x00        // je A80ADC (exit)
    };
    if (std::memcmp(reinterpret_cast<const void*>(checkAddress),
                    expected, sizeof(expected)) != 0)
    {
        OutputDebugStringA("[GRAPHICS] Bullet-mark patch skipped: unexpected code bytes\n");
        DBGONLY(spd::log()->warn(
            "[GRAPHICS] RestoreCoopBulletMarks skipped: unexpected code bytes");)
        return false;
    }
    injector::MakeNOP(checkAddress + 7, 6, true);
    DBGONLY(spd::log()->info(
        "[GRAPHICS] RestoreCoopBulletMarks: creation gate bypassed (experimental)");)
    return true;
}

#include "CoopRuntime.h"
#include "CoopMenuRuntime.h"

void Init()
{
    CIniReader iniReader("");
    DBGONLY(spd::log()->info("[INIT] RE:Rev2 persistent co-op HUD/input + selectable subtitle mode build loaded");)
    auto bSkipIntro = iniReader.ReadInteger("MAIN", "SkipIntro", 1) != 0;
    auto bBorderlessWindowed = iniReader.ReadInteger("MAIN", "BorderlessWindowed", 1) != 0;
    auto bDisableDamageOverlay = iniReader.ReadInteger("MAIN", "DisableDamageOverlay", 1) != 0;
    auto bDisableFilmGrain = iniReader.ReadInteger("MAIN", "DisableFilmGrain", 1) != 0;
    auto bDisableFade = iniReader.ReadInteger("MAIN", "DisableFade", 0) != 0;
    auto bDisableGUICommandFar = iniReader.ReadInteger("MAIN", "DisableGUICommandFar", 0) != 0;
    fFOVFactor = iniReader.ReadFloat("MAIN", "FOVFactor", 1.0f);
    if (fFOVFactor <= 0.0f) fFOVFactor = 1.0f;
    bDisableCreateQuery = iniReader.ReadInteger("MAIN", "DisableCreateQuery", 0) != 0;
    auto bAutoclicker = iniReader.ReadInteger("MAIN", "Autoclicker", 0) != 0;
    nForceLogo = std::clamp(iniReader.ReadInteger("MAIN", "ForceLogo", 0), 0, 4);
    LoadHudTuningFromIni(); // ✅ Load your [HUD] values from INI
    if (iniReader.ReadInteger("GRAPHICS", "DisableCoopEffectFilter", 0) != 0)
        DisableCoopEffectExclusionFilter();
    if (iniReader.ReadInteger("GRAPHICS", "RestoreCoopBulletMarks", 0) != 0)
        EnableCoopBulletMarkCreation();
    if (bSkipIntro)
    {
        injector::WriteMemory<uint8_t>(0xA62A74, 0xEB, true);
        injector::WriteMemory<uint16_t>(0xA62A9D, 0x9090, true);
    }

    // unrestrict resolutons
    injector::MakeNOP(0xCC63CA, 2);
    injector::MakeNOP(0xCC63D1, 2);

    // overwriting aspect ratio
    hook::pattern("0F 84 ? ? ? ? 48 ? ? 48 ? ? 89 8E").for_each_result([](hook::pattern_match match)
        {
            struct hook_ecx_edx {
                void operator()(injector::reg_pack& regs) {
                    ResX = regs.ecx;
                    ResY = regs.edx;

                    if (((float)ResX / (float)ResY) < defaultAspectRatio)
                    {
                        ResY = 9 * ResX / 16;
                        regs.edx = ResY;
                    }
                }
            };
            injector::MakeInline<hook_ecx_edx>(match.get<void>(0), match.get<void>(12));
        });

    hook::pattern("0F 84 ? ? ? ? 48 ? ? 48 ? ? 89 9E").for_each_result([](hook::pattern_match match)
        {
            struct hook_ebx_edi {
                void operator()(injector::reg_pack& regs) {
                    ResX = regs.ebx;
                    ResY = regs.edi;

                    if (((float)ResX / (float)ResY) < defaultAspectRatio)
                    {
                        ResY = 9 * ResX / 16;
                        regs.edi = ResY;
                    }
                }
            };
            injector::MakeInline<hook_ebx_edi>(match.get<void>(0), match.get<void>(12));
        });

    // movies fix for ultra wide
    {
        static auto DrawPrimitiveHook = safetyhook::create_mid(0xCC8788, [](SafetyHookContext& regs)
            {
                auto g_device = (IDirect3DDevice9*)regs.edi;

                // switch to a x-scaling vertex shader if drawing FMVs
                IDirect3DPixelShader9* frag;
                g_device->GetPixelShader(&frag);
                if (frag != g_wmvYuvDecodePixelShader)
                    return;

                IDirect3DVertexShader9* vert;
                g_device->GetVertexShader(&vert);
                if (vert != g_screenVertexShader)
                    return;

                g_device->SetVertexShader(g_myScreenVertexShader);
                float horzScaleFactor = defaultAspectRatio / GetAspectRatio();
                float horizontalOffset = 0.0f;
                if (bDualMonitorMode && !IsSplitScreenActive())
                {
                    uint32_t physicalWidth = 0;
                    uint32_t physicalHeight = 0;
                    const bool hasPhysicalCanvas = GetPhysicalRendererSize(
                        physicalWidth, physicalHeight);
                    const bool isCommonMenuWmv = IsPauseCommonMenu(
                        GetActivePauseCommonMenu());

                    if (isCommonMenuWmv)
                    {
                        // The animated main-menu background is WMV too, but
                        // it is already rendered into the native W/2 target.
                        // A real FMV can report that same half-width D3D
                        // viewport, so the live CommonMenu controller is the
                        // discriminator; viewport dimensions are not.
                        if (hasPhysicalCanvas)
                        {
                            const float localAspect =
                                (static_cast<float>(physicalWidth) * 0.5f) /
                                static_cast<float>(physicalHeight);
                            horzScaleFactor = defaultAspectRatio / localAspect;
                        }
                        horizontalOffset = 0.0f;
                    }
                    else
                    {
                        // A real full-canvas FMV maps from NDC [-1,+1] into
                        // the left equal-monitor viewport [-1,0]. Present then
                        // mirrors that completed viewport to the right.
                        constexpr float leftFraction = 1.0f / 2.0f;
                        horzScaleFactor = leftFraction;
                        horizontalOffset = -(1.0f - leftFraction);
                        InterlockedExchange(&gDualMonitorLastFmvPresentSerial,
                            InterlockedCompareExchange(
                                &gDualMonitorPresentSerial, 0, 0));
                    }
                }
                const std::array<float, 4> shaderConsts = { horzScaleFactor, 0.0f, 0.0f, 0.0f };
                g_device->SetVertexShaderConstantF(20, shaderConsts.data(), 1);
                const std::array<float, 4> offsetConsts = { horizontalOffset, 0.0f, 0.0f, 0.0f };
                g_device->SetVertexShaderConstantF(21, offsetConsts.data(), 1);
            });
    }

    // split screen windows dimensions
    injector::MakeCALL(0x4AE6E8, SplitScreenSetupTop, true);
    injector::MakeCALL(0x4AE732, SplitScreenSetupBottom, true);

    if (bDualMonitorMode)
    {
        dualmonitor::RequestInstall();
        rev2coop::Report(
            "[DUAL] Waiting for the renderer/device before installing non-split hooks");
    }

    // GUI
    injector::MakeJMP(0xE18040, sub_E18040_rescale, true);

    injector::WriteMemory(uGUIFade, sub_E18040_fade, true);
    injector::WriteMemory(uGUICommandBase, sub_E18040, true);
    injector::WriteMemory(uGUICommandFar, sub_E18040_offset, true);
    injector::WriteMemory(uGUICommandNear, sub_E18040, true);

    // Keep the existing single-monitor pause path byte-for-byte native: these
    // three class slots are replaced only during a DualMonitorMode=1 startup.
    // A later F5 reload may disable replay safely, but enabling it requires a
    // restart so the guarded vtable wrappers can be installed.
    if (bDualMonitorMode)
    {
        rev2coop::Report(InstallDualMonitorPauseGui()
            ? "[DUAL] Pause menu, purpose and guide duplicated for the right monitor"
            : "[DUAL] Pause duplication skipped: native GUI draw-slot guard failed");
        rev2coop::Report(InstallDualMonitorFileText()
            ? "[DUAL] Active story FileText notes duplicated for the right monitor"
            : "[DUAL] FileText duplication skipped: native GUI draw-slot guard failed");
    }

    if (bDisableDamageOverlay)
    {
        injector::WriteMemory(uGUIDamage, sub_E18040_nop, true);
        injector::WriteMemory(uGUIDamage2, sub_E18040_nop, true);
    }
    else
    {
        injector::WriteMemory(uGUIDamage, sub_E18040_stretch, true);
        injector::WriteMemory(uGUIDamage2, sub_E18040_stretch, true);
    }

    if (iniReader.ReadInteger("COOP", "ViewportHud", 1) != 0)
    {
        rev2coop::Report(rev2coop::InstallHud()
            ? "[COOP] SP layout/height-uniform geometry enabled for Equip/Heal/HealNum/Flash/ReticleBase"
            : "[COOP] HUD skipped: native code/vtable guard failed or allocation unavailable");
        rev2coop::Report(InstallFixedHudActionPrompt()
            ? "[COOP] Fixed ActionIcon2 HUD prompt uses SP-local layout and split-safe draw"
            : "[COOP] Fixed ActionIcon2 HUD prompt skipped: native code/vtable guard failed");
    }
    if (iniReader.ReadInteger("COOP", "NativeKeyboardMousePlayer1", 1) != 0)
        rev2coop::Report(rev2coop::InstallInput()
            ? "[COOP] Native P1 keyboard/mouse isolation and bridge capture coordination enabled"
            : "[COOP] Native input skipped: code guard failed or allocation unavailable");
    if (iniReader.ReadInteger("COOP", "AdaptiveInventory", 1) != 0)
        rev2coop::Report(rev2coop::InstallInventory()
            ? "[COOP] Adaptive Campaign Inventory/Quick Menu and item previews enabled"
            : "[COOP] Inventory skipped: native code/vtable guard failed or allocation unavailable");
    const auto partnerViewport =
        iniReader.ReadInteger("COOP", "PartnerCommandViewport", 1) != 0;
    const auto keyboardPartnerCommand =
        iniReader.ReadInteger("COOP", "KeyboardPartnerCommand", 1) != 0;
    if (!bDisableGUICommandFar && (partnerViewport || keyboardPartnerCommand))
        rev2coop::Report(rev2coop::InstallPartnerCommand(keyboardPartnerCommand)
            ? "[COOP] Viewport-local Near/Far partner command and P1 keyboard Tab enabled"
            : "[COOP] Partner command skipped: native code/vtable guard failed or allocation unavailable");
    else if (bDisableGUICommandFar && (partnerViewport || keyboardPartnerCommand))
        rev2coop::Report("[COOP] Partner command skipped because MAIN.DisableGUICommandFar is enabled");
    // Publish installed hooks before starting the background IPC reader.
    const auto tuningThread = CreateThread(nullptr, 0, IniHotkeyThread, nullptr, 0, nullptr);
    if (tuningThread) CloseHandle(tuningThread);

    //Camera near clip fix
    injector::MakeCALL(0x4B17CA, sub_B82960, true);
    injector::MakeCALL(0x4B6F67, sub_B82960, true);
    injector::MakeCALL(0x9D543D, sub_B82960, true);
    injector::MakeCALL(0xC89DE9, sub_B82960, true);
    injector::MakeCALL(0xCA97D5, sub_B82960, true);
    injector::MakeCALL(0xDFEA3A, sub_B82960, true);
    injector::MakeCALL(0xE0C9ED, sub_B82960, true);
    injector::MakeCALL(0xE720D2, sub_B82960, true);
    injector::MakeCALL(0xF0A652, sub_B82960, true);
    injector::MakeCALL(0xF28D7B, sub_B82960, true);
    injector::MakeCALL(0xF4E190, sub_B82960, true);
    injector::MakeCALL(0x102F9D9, sub_B82960, true);

    //3d items in the inventory
    injector::MakeCALL(0x8931DE, sub_96C410, true);
    injector::MakeCALL(0x8C1B3E, sub_96C410, true);
    injector::MakeCALL(0x8CEB99, sub_96C410, true);
    injector::MakeCALL(0x8F7A29, sub_96C410, true);
    injector::MakeCALL(0x8FA254, sub_96C410, true);
    injector::MakeCALL(0x8FA2E5, sub_96C410, true);
    injector::MakeCALL(0x93D63C, sub_96C410, true);

    //disable shader overlays (don't scale to fullscreen)
    {
        injector::MakeCALL(0xFFB9E2, CreateVertexShaderHook, true);
        injector::MakeCALL(0xFFBA31, CreatePixelShaderHook, true);

        //struct SetVertexShaderHook
        //{
        //    void operator()(injector::reg_pack& regs)
        //    {
        //        if (IsSplitScreenActive() || GetDiff() > 1.0f)
        //        {
        //            auto pShader = (IDirect3DVertexShader9*)regs.ecx;
        //            if (pShader == shader_4F0EE939)
        //            {
        //                regs.ecx = 0;
        //            }
        //        }
        //        *(uint32_t*)(regs.ebx + 0x24) = regs.ecx;
        //        regs.eax = *(uint32_t*)(regs.esi + 0x0);
        //    }
        //}; injector::MakeInline<SetVertexShaderHook>(0xCCD0A4);
    }

    if (bDisableFilmGrain)
    {
        injector::WriteMemory<uint8_t>(0x0141664C, 'r', true);
        injector::WriteMemory<uint8_t>(0x01416668, 'r', true);
    }

    if (bDisableFade)
    {
        injector::WriteMemory(uGUIFade, sub_E18040_nop, true);
    }

    if (bDisableGUICommandFar)
    {
        injector::WriteMemory(uGUICommandFar, sub_E18040_nop, true);
    }

    if (bBorderlessWindowed)
    {
        IATHook::Replace(GetModuleHandleA(NULL), "USER32.DLL",
            std::forward_as_tuple("CreateWindowExA", WindowedModeWrapper::CreateWindowExA_Hook),
            std::forward_as_tuple("CreateWindowExW", WindowedModeWrapper::CreateWindowExW_Hook),
            std::forward_as_tuple("SetWindowLongA", WindowedModeWrapper::SetWindowLongA_Hook),
            std::forward_as_tuple("SetWindowLongW", WindowedModeWrapper::SetWindowLongW_Hook),
            std::forward_as_tuple("AdjustWindowRect", WindowedModeWrapper::AdjustWindowRect_Hook),
            std::forward_as_tuple("SetWindowPos", WindowedModeWrapper::SetWindowPos_Hook)
        );
    }

    //Episode 4 finale stuck controls fix
    {
        injector::WriteMemory<uint8_t>(0xC21007 + 1, 0x79, true);
    }

    {
        injector::WriteMemory(0xA97206 + 4, 1000, true); //max fps
        injector::WriteMemory(0xA9796C + 4, 1000, true); //max fps
    }

    if (bDisableCreateQuery)
    {
        auto pattern = hook::pattern("51 80 B9 ? ? ? ? ? 8B 91");
        injector::MakeJMP(pattern.get_first(), gpuCommandBufferSync, true);
    }

    if (bAutoclicker)
    {
        pXInputGetState = std::move(IATHook::Replace(GetModuleHandleA(NULL), "XINPUT1_3.dll",
            std::forward_as_tuple("XInputGetState@2", XInputGetStateHook)
        )["XInputGetState@2"]);

        auto pattern = hook::pattern("E8 ? ? ? ? 8B D0 85 D2 75 13 8B 07 8B CF FF 50 60 56 FF 15 ? ? ? ? 5E 5F C2 0C 00 8B CA 53 8D 59 01 8D A4 24");
        hb_954B40.fun = injector::MakeCALL(pattern.get_first(), sub_954B40, true).get();
    }

    if (nForceLogo)
    {
        auto pattern = hook::pattern("E8 ? ? ? ? 83 F8 03 77 ? FF 24 85 ? ? ? ? 6A 01 68 04 8F 39 01");
        injector::MakeCALL(pattern.get_first(), sub_984240, true);

        pattern = hook::pattern("E8 ? ? ? ? 83 F8 03 0F 87 ? ? ? ? FF 24 85 ? ? ? ? 68 E8 8E 39 01");
        injector::MakeCALL(pattern.get_first(), sub_984240, true);

        pattern = hook::pattern("E8 ? ? ? ? 83 F8 03 77 ? FF 24 85 ? ? ? ? 6A 01 68 E8 EC 3B 01");
        injector::MakeCALL(pattern.get_first(), sub_984240, true);

        pattern = hook::pattern("E8 ? ? ? ? 83 F8 03 0F 87 ? ? ? ? FF 24 85 ? ? ? ? 68 B4 EC 3B 01");
        injector::MakeCALL(pattern.get_first(), sub_984240, true);
    }

    {
        static auto sPlayerPtr = *hook::get_pattern<void*>("8B 0D ? ? ? ? 56 E8 ? ? ? ? 85 C0 74 7B 8B C8", 2);

        LEDEffects::Inject([]()
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));

                if (sPlayerPtr)
                {
                    static auto sub_6E6A70 = [](int* _this) -> void*
                        {
                            if (!_this)
                                return nullptr;

                            auto j = 0;
                            for (auto i = _this + 8; !*i || *(DWORD*)(*i + 0x7920); ++i)
                            {
                                if (++j >= 8)
                                    return nullptr;
                            }
                            return (void*)_this[j + 8];
                        };
                    auto pPlayerPtr = sub_6E6A70(*(int**)sPlayerPtr);

                    if (pPlayerPtr)
                    {
                        auto Player1Health = PtrWalkthrough<int32_t>(&pPlayerPtr, 0x1A08);
                        auto Player2Health = PtrWalkthrough<int32_t>(&pPlayerPtr, 0x1A0C);

                        if (Player1Health && Player2Health)
                        {
                            auto health1 = *Player1Health;
                            auto health2 = *Player2Health;
                            if (health1 > 1)
                            {
                                if (health1 <= 250) {
                                    LEDEffects::SetLightingLeftSide(26, 4, 4, true, false); //red
                                    LEDEffects::DrawCardiogram(100, 0, 0, 0, 0, 0); //red
                                }
                                else if (health1 <= 350) {
                                    LEDEffects::SetLightingLeftSide(50, 30, 4, true, false); //orange
                                    LEDEffects::DrawCardiogram(67, 0, 0, 0, 0, 0); //orange
                                }
                                else {
                                    LEDEffects::SetLightingLeftSide(10, 30, 4, true, false);  //green
                                    LEDEffects::DrawCardiogram(0, 100, 0, 0, 0, 0); //green
                                }
                            }
                            else
                            {
                                LEDEffects::SetLightingLeftSide(26, 4, 4, false, true); //red
                                LEDEffects::DrawCardiogram(100, 0, 0, 0, 0, 0, true);
                            }

                            if (health2 > 1)
                            {
                                if (health2 <= 250) {
                                    LEDEffects::SetLightingRightSide(26, 4, 4, true, false); //red
                                    LEDEffects::DrawCardiogramNumpad(100, 0, 0, 0, 0, 0); //red
                                }
                                else if (health2 <= 350) {
                                    LEDEffects::SetLightingRightSide(50, 30, 4, true, false); //orange
                                    LEDEffects::DrawCardiogramNumpad(67, 0, 0, 0, 0, 0); //orange
                                }
                                else {
                                    LEDEffects::SetLightingRightSide(10, 30, 4, true, false);  //green
                                    LEDEffects::DrawCardiogramNumpad(0, 100, 0, 0, 0, 0); //green
                                }
                            }
                            else
                            {
                                LEDEffects::SetLightingRightSide(26, 4, 4, false, true); //red
                                LEDEffects::DrawCardiogramNumpad(100, 0, 0, 0, 0, 0, true);
                            }
                        }
                        else
                        {
                            LogiLedStopEffects();
                            LEDEffects::SetLighting(90, 36, 3);
                        }
                    }
                    else
                    {
                        LogiLedStopEffects();
                        LEDEffects::SetLighting(90, 36, 3);
                    }
                }
            });
    }
}

CEXP void InitializeASI()
{
    std::call_once(CallbackHandler::flag, []()
        {
            CallbackHandler::RegisterCallbackAtGetSystemTimeAsFileTime(Init, hook::pattern("F3 0F 5C 15 ? ? ? ? F3 0F 59 E5"));
        });
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        if (!IsUALPresent()) { InitializeASI(); }
    }
    else if (reason == DLL_PROCESS_DETACH)
    {

    }
    return TRUE;
}
