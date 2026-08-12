/*
 * compose.c - the z-order half of the compositor (GUI-4).
 *
 * Wine's server deliberately does not clip top-level siblings out of a
 * window's surface region: "we don't clip out top-level siblings as that's
 * up to the native windowing system" (server/window.c, get_visible_region).
 * Under winex11/winewayland the host compositor owns that occlusion; here
 * winefb IS the native windowing system, so the driver asks the server who
 * is above and clips its flushes accordingly, and — the other half of the
 * same delegation — repairs what a moved window uncovers (blit.c).
 *
 * Queried fresh per use rather than cached: the answer is two small server
 * round-trips over state that any process may change at any moment, and a
 * cache would need exactly the cross-process invalidation protocol this
 * design avoids. Staleness is bounded by one flush: both the clip and the
 * repaint requests derive from the same server rectangles, so the picture
 * converges on the next flush of either side.
 */

#include "winefb.h"
#include "wine/debug.h"
#include "wine/server.h"

WINE_DEFAULT_DEBUG_CHANNEL(winefb);

/* The desktop's visible top-level windows, topmost first (the get_window_list
 * reply order is the same walk the server's own hit-testing does in
 * shallow_window_from_point), with screen rects. A window this process
 * cannot resolve answers 0, which reads as invisible -- the safe direction.
 *
 * Every read here is a RAW server request on purpose, style included: this
 * runs from winefb_surface_flush, INSIDE win32u's per-surface mutex, and a
 * blocking NtUser* call here is a lock-order inversion against every
 * user-lock -> surface-mutex path win32u has (DestroyWindow holding the
 * user lock while releasing the window surface deadlocked against a
 * concurrent flush doing exactly that -- the user32:msg wedge, two threads
 * parked forever on each other's mutex). NtUserGetWindowLongW looks
 * innocent but takes the user lock for own-process windows; the server's
 * get_window_info answers the same style for ANY window (it is what win32u
 * itself uses for other-process windows) with no client lock at all. */
static UINT query_visible_toplevels( struct winefb_toplevel *out, UINT max_count )
{
    user_handle_t handles[WINEFB_MAX_TOPLEVELS];
    unsigned int count = 0, i;
    UINT found = 0;
    NTSTATUS status;

    SERVER_START_REQ( get_window_list )
    {
        req->desktop  = 0;
        req->handle   = 0; /* top-level windows of the current desktop */
        req->tid      = 0;
        req->children = 0;
        wine_server_set_reply( req, handles, sizeof(handles) );
        status = wine_server_call( req );
        count = reply->count;
    }
    SERVER_END_REQ;
    if (status || count > WINEFB_MAX_TOPLEVELS) return 0;

    for (i = 0; i < count && found < max_count; i++)
    {
        RECT rect, client;
        unsigned int style = 0;

        SERVER_START_REQ( get_window_info )
        {
            req->handle = handles[i];
            req->offset = GWL_STYLE;
            req->size   = sizeof(LONG);
            if (!wine_server_call( req )) style = reply->info;
        }
        SERVER_END_REQ;
        if (!(style & WS_VISIBLE)) continue;

        /* One reply carries both rects; the client one is what a
         * rect-scoped invalidation needs, since RedrawWindow's rect is
         * client-relative (blit.c invalidate_covered). */
        SERVER_START_REQ( get_window_rectangles )
        {
            req->handle   = handles[i];
            req->relative = COORDS_SCREEN;
            status = wine_server_call( req );
            rect.left     = reply->window.left;
            rect.top      = reply->window.top;
            rect.right    = reply->window.right;
            rect.bottom   = reply->window.bottom;
            client.left   = reply->client.left;
            client.top    = reply->client.top;
            client.right  = reply->client.right;
            client.bottom = reply->client.bottom;
        }
        SERVER_END_REQ;
        if (status || IsRectEmpty( &rect )) continue;

        out[found].hwnd = wine_server_ptr_handle( handles[i] );
        out[found].rect = rect;
        out[found].client = client;
        found++;
    }
    return found;
}

/* Screen rects of the visible top-level windows strictly ABOVE hwnd in the
 * desktop's z-order. Returns how many were filled. If hwnd never appears
 * in the list (foreign desktop, destroyed, hidden mid-flush), nothing is
 * subtracted -- the defensive answer is yesterday's last-writer-wins, not
 * a hole in the picture. */
UINT winefb_windows_above( HWND hwnd, RECT *rects, UINT max_count )
{
    struct winefb_toplevel list[WINEFB_MAX_TOPLEVELS];
    UINT count = query_visible_toplevels( list, WINEFB_MAX_TOPLEVELS );
    UINT i, above = 0;
    user_handle_t top_window = 0;

    /* The desktop window is desktop->top_window — the PARENT of every entry
     * in the list, so the walk below can never find it and would fall to the
     * nothing-subtracted answer. Before GUI-6 that could not matter: the
     * desktop's surface flushed once, before any other window existed, and
     * was painted over ever after. An explorer-owned desktop repaints on
     * WM_PAINT at any moment, and that flush must clip below EVERY top-level
     * or the background erase eats whichever window last reached the scanout
     * (the gui5con vanishing-console bug: only the text lines conhost
     * incrementally redrew survived). Same raw-request rule as above: no
     * NtUser* inside a flush. force=0 — a flushing surface implies the
     * desktop window already exists. */
    SERVER_START_REQ( get_desktop_window )
    {
        req->force = 0;
        if (!wine_server_call( req )) top_window = reply->top_window;
    }
    SERVER_END_REQ;
    if (top_window && hwnd == wine_server_ptr_handle( top_window ))
    {
        for (i = 0; i < count && above < max_count; i++) rects[above++] = list[i].rect;
        return above;
    }

    for (i = 0; i < count; i++)
    {
        if (list[i].hwnd == hwnd) return above;
        if (above < max_count) rects[above++] = list[i].rect;
    }
    return 0; /* hwnd not found */
}

/* Every visible top-level EXCEPT exclude -- the candidates a vacated area
 * may have uncovered (blit.c winefb_window_pos_changed). */
UINT winefb_other_toplevels( HWND exclude, struct winefb_toplevel *out, UINT max_count )
{
    struct winefb_toplevel list[WINEFB_MAX_TOPLEVELS];
    UINT count = query_visible_toplevels( list, WINEFB_MAX_TOPLEVELS );
    UINT i, others = 0;

    for (i = 0; i < count && others < max_count; i++)
    {
        if (list[i].hwnd == exclude) continue;
        out[others++] = list[i];
    }
    return others;
}
