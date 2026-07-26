/*
 * fontsmoke.c — the font-metrics oracle actually has a font backend.
 *
 * ORACLE-ONLY, deliberately. It lives outside tests/ntapi/ so the harness's
 * all_tests() sweep never picks it up: it links gdi32, which the proskrnl
 * ntapi image does not carry, and it asks nothing about the KERNEL. It is a
 * check on the test *equipment*, not on proskrnl (docs/14).
 *
 * Why it exists (docs/03 "the font oracle"): GUI-3 reconfigured the pinned
 * Wine --with-freetype against the pinned third_party/freetype, making it the
 * font-metrics oracle. The failure mode that change introduces is silent.
 * win32u does not LINK its font backend, it dlopen()s SONAME_LIBFREETYPE at
 * run time, and when that fails it does not fail — it proceeds with no fonts
 * at all. A missing LD_LIBRARY_PATH, an unbuilt native library, or a
 * configure that quietly turned fonts back off would all leave the oracle
 * green here and silently font-less, which is exactly the divergence the
 * oracle was rebuilt to remove. So: ask it for a font and check it answers.
 *
 * What this does NOT do is compare numbers between oracle and target. That
 * differential is GUI-5's (docs/02); this only pins that the oracle side of
 * it is real.
 */
#include "ntapi.h"

/* Tahoma: shipped by the pinned tree as a real TrueType face (fonts/tahoma.ttf,
 * generated from its own .sfd) and baked onto the GUI images by the Makefile's
 * WINE_FONTS, so both sides have it by the same provenance. */
static const WCHAR tahomaW[] = {'T', 'a', 'h', 'o', 'm', 'a', 0};

static int face_is(const WCHAR *face, const WCHAR *want)
{
    int i;
    for (i = 0; want[i]; i++)
        if (face[i] != want[i])
            return 0;
    return face[i] == 0;
}

START_TEST(fontsmoke)
{
    TEXTMETRICW tm;
    WCHAR face[LF_FACESIZE];
    LOGFONTW lf;
    HFONT font, old;
    HDC dc;
    int i, got;

    dc = CreateCompatibleDC(NULL);
    ok(dc != NULL, "CreateCompatibleDC failed");
    if (!dc)
        return;

    /* A memory DC needs no display driver, so this works under --without-x. */
    for (i = 0; i < (int)sizeof(lf); i++)
        ((char *)&lf)[i] = 0;
    lf.lfHeight = -16;
    lf.lfCharSet = DEFAULT_CHARSET;
    for (i = 0; tahomaW[i]; i++)
        lf.lfFaceName[i] = tahomaW[i];

    font = CreateFontIndirectW(&lf);
    ok(font != NULL, "CreateFontIndirectW failed");
    if (!font)
    {
        DeleteDC(dc);
        return;
    }
    old = SelectObject(dc, font);

    /* With no backend, font matching falls back to a built-in stand-in and
     * this comes back as something other than the face that was asked for. */
    got = GetTextFaceW(dc, LF_FACESIZE, face);
    ok(got > 0, "GetTextFaceW returned %d", got);
    ok(got > 0 && face_is(face, tahomaW),
       "selected face is not Tahoma — the font backend is missing "
       "(check SONAME_LIBFREETYPE and LD_LIBRARY_PATH)");

    ok(GetTextMetricsW(dc, &tm) != 0, "GetTextMetricsW failed");
    ok(tm.tmHeight > 0, "tmHeight is %d, expected a real glyph height", (int)tm.tmHeight);
    ok(tm.tmAveCharWidth > 0, "tmAveCharWidth is %d, expected a real advance",
       (int)tm.tmAveCharWidth);

    /* A scalable face reports itself as such; a bitmap stand-in would not. */
    ok((tm.tmPitchAndFamily & TMPF_TRUETYPE) != 0,
       "Tahoma did not come back as TrueType (tmPitchAndFamily = 0x%x)",
       (unsigned)tm.tmPitchAndFamily);

    SelectObject(dc, old);
    DeleteObject(font);
    DeleteDC(dc);
}
