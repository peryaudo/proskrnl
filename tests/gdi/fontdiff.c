/*
 * fontdiff.c — the font-metrics differential (GUI-5).
 *
 * GUI-3 made the pinned Wine the font-metrics oracle: both sides share the
 * FreeType backend, the FreeType version (2.13.3, built from one file list
 * by tools/build_freetype.sh) and the font set (the pinned tree's fonts/,
 * baked at C:\windows\fonts). fontsmoke.c pins that the oracle's backend is
 * alive; THIS test is the deferred half (docs/03 "the font oracle"): the
 * same measurement run on both sides, compared number for number.
 *
 * ONE binary, both runners, ONE golden:
 *   oracle    run.sh oracle() runs it and diffs its [KTEST] fontdiff lines
 *             against tests/gdi/fontdiff.golden on every run (regenerate
 *             with FONTDIFF_REFRESH=1 and commit the diff) — the golden can
 *             never go silently stale;
 *   proskrnl  the gui5 leg bakes and runs the same binary; check_gui5.py
 *             diffs the guest's lines against the same golden.
 *
 * Exact integer equality, no epsilon: identical backend + font bytes +
 * 96 dpi means an off-by-one is a real divergence, never noise. The dpi=
 * header line exists so a DPI mismatch convicts the environment rather than
 * surfacing as a hundred wrong widths; the done n= trailer makes truncation
 * visible. Every face selection is ok()-checked so a silent fallback face
 * (the failure mode fontsmoke exists for) fails the test instead of diffing
 * another font's numbers.
 */
#include "ntapi.h"

struct face_case
{
    const WCHAR *face; /* what CreateFontIndirectW asks for */
    const char *name;  /* the same, ASCII + underscores, for the log line */
    int weight;
};

/* Family names verified against the pinned tree's .sfd sources: the third
 * face is "Courier" (fonts/courier.sfd), not "Courier New" — the pinned set
 * does not carry Courier New. */
static const struct face_case faces[] = {
    {L"Tahoma", "Tahoma", 400},
    {L"Tahoma", "Tahoma", 700},
    {L"MS Sans Serif", "MS_Sans_Serif", 400},
    {L"Courier", "Courier", 400},
};

/* Both mapping directions: negative = em height, positive = cell height. */
static const int heights[] = {-11, -13, -16, -24, 16};

/* Pangram + digits: every letter's advance participates in the extent. */
static const WCHAR sample[] = L"The quick brown fox jumps over the lazy dog 0123456789";

static int face_matches(const WCHAR *got, const WCHAR *want)
{
    int i;
    for (i = 0; want[i]; i++)
        if (got[i] != want[i])
            return 0;
    return got[i] == 0;
}

START_TEST(fontdiff)
{
    HDC dc;
    int fi, hi, lines = 0;

    /* A memory DC needs no display driver: works under the --without-x
     * oracle and over winefb on the target alike (the fontsmoke precedent). */
    dc = CreateCompatibleDC(NULL);
    ok(dc != NULL, "CreateCompatibleDC failed");
    if (!dc)
        return;

    ntapi_printf("[KTEST] fontdiff dpi=%d,%d\n", GetDeviceCaps(dc, LOGPIXELSX),
                 GetDeviceCaps(dc, LOGPIXELSY));

    for (fi = 0; fi < (int)(sizeof(faces) / sizeof(faces[0])); fi++)
    {
        for (hi = 0; hi < (int)(sizeof(heights) / sizeof(heights[0])); hi++)
        {
            LOGFONTW lf;
            HFONT font, old;
            TEXTMETRICW tm;
            WCHAR got[LF_FACESIZE];
            SIZE ext;
            INT cw[26], cwi, cww, cw0, cwsp, cwsum;
            ABC abc;
            BOOL has_abc;
            int i, len;

            for (i = 0; i < (int)sizeof(lf); i++)
                ((char *)&lf)[i] = 0;
            lf.lfHeight = heights[hi];
            lf.lfWeight = faces[fi].weight;
            lf.lfCharSet = DEFAULT_CHARSET;
            for (i = 0; faces[fi].face[i]; i++)
                lf.lfFaceName[i] = faces[fi].face[i];

            font = CreateFontIndirectW(&lf);
            ok(font != NULL, "%s h=%d: CreateFontIndirectW failed", faces[fi].name, heights[hi]);
            if (!font)
                continue;
            old = SelectObject(dc, font);

            /* The face must be the one asked for — a fallback face would
             * make every number below a lie (see the header comment). */
            i = GetTextFaceW(dc, LF_FACESIZE, got);
            ok(i > 0 && face_matches(got, faces[fi].face),
               "%s h=%d: selected face is not the requested one", faces[fi].name, heights[hi]);

            ok(GetTextMetricsW(dc, &tm) != 0, "%s h=%d: GetTextMetricsW failed", faces[fi].name,
               heights[hi]);

            for (len = 0; sample[len]; len++)
                ;
            ok(GetTextExtentPoint32W(dc, sample, len, &ext) != 0,
               "%s h=%d: GetTextExtentPoint32W failed", faces[fi].name, heights[hi]);

            ok(GetCharWidth32W(dc, 'i', 'i', &cwi) != 0, "%s h=%d: GetCharWidth32W('i') failed",
               faces[fi].name, heights[hi]);
            ok(GetCharWidth32W(dc, 'W', 'W', &cww) != 0, "%s h=%d: GetCharWidth32W('W') failed",
               faces[fi].name, heights[hi]);
            ok(GetCharWidth32W(dc, '0', '0', &cw0) != 0, "%s h=%d: GetCharWidth32W('0') failed",
               faces[fi].name, heights[hi]);
            ok(GetCharWidth32W(dc, ' ', ' ', &cwsp) != 0, "%s h=%d: GetCharWidth32W(' ') failed",
               faces[fi].name, heights[hi]);
            cwsum = 0;
            if (GetCharWidth32W(dc, 'A', 'Z', cw))
                for (i = 0; i < 26; i++)
                    cwsum += cw[i];
            else
                ok(0, "%s h=%d: GetCharWidth32W(A..Z) failed", faces[fi].name, heights[hi]);

            /* ABC widths exist only for outline strikes; a bitmap strike
             * (the .fon versions of these families are baked too, and the
             * mapper may pick one at a matching size) answers FALSE. Both
             * sides must pick the SAME strike, so the refusal itself is
             * part of the differential — print it as abc=none. */
            has_abc = GetCharABCWidthsW(dc, 'W', 'W', &abc);

            ntapi_printf("[KTEST] fontdiff face=%s w=%d h=%d"
                         " tm=%d,%d,%d,%d,%d,%d,%d,%d,%d,0x%x,%d"
                         " ext=%dx%d cw=%d,%d,%d,%d,%d",
                         faces[fi].name, faces[fi].weight, heights[hi], (int)tm.tmHeight,
                         (int)tm.tmAscent, (int)tm.tmDescent, (int)tm.tmInternalLeading,
                         (int)tm.tmExternalLeading, (int)tm.tmAveCharWidth, (int)tm.tmMaxCharWidth,
                         (int)tm.tmWeight, (int)tm.tmOverhang, (unsigned)tm.tmPitchAndFamily,
                         (int)tm.tmCharSet, (int)ext.cx, (int)ext.cy, cwi, cww, cw0, cwsp, cwsum);
            if (has_abc)
                ntapi_printf(" abc=%d,%d,%d\n", (int)abc.abcA, (int)abc.abcB, (int)abc.abcC);
            else
                ntapi_printf(" abc=none\n");
            lines++;

            SelectObject(dc, old);
            DeleteObject(font);
        }
    }

    ntapi_printf("[KTEST] fontdiff done n=%d\n", lines);
    DeleteDC(dc);
}
